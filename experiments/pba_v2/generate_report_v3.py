#!/usr/bin/env python3
"""Generate the corrected PBA/2 manuscript artifacts.

The input budget files must come from the corrected observable-feedback runner.
This generator keeps record-level TDR, full-scope TDR, result-replay TDR, and
coverage as separate quantities; it never turns missing latency observations
into a censored-round value.
"""
from __future__ import annotations
import csv, hashlib, json, math, shutil
from collections import defaultdict
from datetime import date
from pathlib import Path
import numpy as np
from independent_protocol_oracle import evaluate as evaluate_protocol_oracle

ROOT=Path(__file__).resolve().parents[2]
RESULTS=ROOT/'experiments'/'pba_v2'/'results'
OUT=RESULTS/'release_v3'
BUDGET_FILES={
    'partition_a': RESULTS/'final_budget_v4'/'partition_a'/'budget_audit_results_release.json',
    'partition_b': RESULTS/'final_budget_v4'/'partition_b'/'budget_audit_results_release.json',
}
SENSITIVITY_PATH=RESULTS/'final_budget_sensitivity'/'sensitivity_summary.json'
FL_PATH=RESULTS/'fl_release_candidate_roster_v6.json'
PROTOCOL_PATH=RESULTS/'protocol_final_v4'/'protocol_attack_matrix_final.json'
TRANSFER_PATH=RESULTS/'transfer_client_45700.json'
LITERATURE_PATH=ROOT/'experiments'/'pba_v2'/'LITERATURE_MATRIX_PBA2_FINAL_2026-09-15.md'
COMPONENTS=(
    'bulletin_bytes_read','snapshot_bytes_read','policy_bytes_read',
    'roster_bytes_read','state_bytes_read','receipt_bytes_read',
    'merkle_proof_bytes_read','opening_bytes_read','update_bytes_read',
    'result_bytes_read','disposition_bytes_read','unattributed_framing_bytes')
SUMMARY_METRICS=(
    'record_level_tdr','full_scope_tdr','full_round_tdr','full_replay_result_tdr',
    'attack_coverage','bytes_read','cpu_ms','wall_ms','first_detection_latency',
    'first_detection_observed','inconclusive','inconclusive_attack_rounds',
    'checks','spot_record_checks','full_round_checks','audit_calls',
    'records_processed','updates_processed',*COMPONENTS)

def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def mean_sd_ci(values):
    vals=[float(v) for v in values if v is not None and np.isfinite(v)]
    if not vals: return None, None, None
    a=np.asarray(vals,dtype=float); m=float(a.mean())
    sd=float(a.std(ddof=1)) if len(a)>1 else 0.0
    ci=float(1.96*sd/math.sqrt(len(a))) if len(a)>1 else 0.0
    return m,sd,ci

def collect_components(row):
    totals={k:0 for k in COMPONENTS}
    for audit_row in (row.get('audit_outcomes') or {}).values():
        itemized=0
        for key in COMPONENTS:
            if key=='unattributed_framing_bytes': continue
            value=int(audit_row.get(key,0) or 0)
            totals[key]+=value; itemized+=value
        totals['unattributed_framing_bytes'] += max(0,int(audit_row.get('total_network_bytes',0) or 0)-itemized)
    return totals

def read_budget_rows():
    all_rows=[]; configs=[]; provenance=[]; seed_sets={}
    for label,path in BUDGET_FILES.items():
        if not path.exists(): raise FileNotFoundError(path)
        data=json.loads(path.read_text(encoding='utf8'))
        configs.append(data['configuration']); seed_sets[label]=set()
        provenance.append({'partition':label,'path':str(path),'sha256':sha256(path)})
        for row in data['rows']:
            seed=int(row['seed']); seed_sets[label].add(seed)
            enriched=dict(row); enriched['partition']=label; enriched['source_file']=str(path)
            enriched.update(collect_components(row))
            if sum(enriched[k] for k in COMPONENTS)!=int(row['bytes_read']):
                raise ValueError(f'byte accounting mismatch {label}/{seed}/{row["method"]}/{row["attack"]}')
            all_rows.append(enriched)
    norm=[{k:v for k,v in c.items() if k not in ('seeds','seed_start')} for c in configs]
    if norm[0]!=norm[1]: raise ValueError('budget configurations differ outside seed partition')
    if seed_sets['partition_a'] & seed_sets['partition_b']: raise ValueError('overlapping seed partitions')
    all_rows.sort(key=lambda x:(x['attack'],x['method'],int(x['seed'])))
    return all_rows,configs[0],provenance

def aggregate(rows):
    groups=defaultdict(list)
    for row in rows: groups[(row['attack'],row['method'])].append(row)
    summary=[]
    for (attack,method),group in sorted(groups.items()):
        item={'attack':attack,'method':method,'n':len(group),'partitions':sorted({x['partition'] for x in group})}
        for key in SUMMARY_METRICS:
            m,sd,ci=mean_sd_ci([x.get(key) for x in group])
            item[f'{key}_mean']=m; item[f'{key}_sd']=sd; item[f'{key}_95ci']=ci
        item['detected_latency_n']=sum(bool(x.get('first_detection_observed')) for x in group)
        item['latency_censored_n']=len(group)-item['detected_latency_n']
        summary.append(item)
    return summary

def paired_comparison(rows):
    """Compute seed-paired adaptive-minus-uniform estimates.

    Each seed contributes one already-aggregated workload value.  The reported
    interval is the normal 95% CI of the paired differences, not an independent
    CI of the two method means.
    """
    by_attack_seed=defaultdict(dict)
    for row in rows:
        if row['method'] in {'adaptive','uniform'}:
            by_attack_seed[(row['attack'],int(row['seed']))][row['method']]=row
    out=[]
    for attack in sorted({a for a,_ in by_attack_seed}):
        pairs=[v for (a,_),v in by_attack_seed.items() if a==attack and {'adaptive','uniform'} <= set(v)]
        for metric in ('record_level_tdr','bytes_read'):
            diffs=np.asarray([float(p['adaptive'][metric])-float(p['uniform'][metric]) for p in pairs],dtype=float)
            m=float(diffs.mean()) if len(diffs) else None
            sd=float(diffs.std(ddof=1)) if len(diffs)>1 else 0.0
            ci=float(1.96*sd/math.sqrt(len(diffs))) if len(diffs)>1 else 0.0
            out.append({'attack':attack,'metric':metric,'n':len(diffs),'difference_mean':m,
                        'difference_sd':sd,'difference_95ci':ci,
                        'ci_low':(m-ci if m is not None else None),
                        'ci_high':(m+ci if m is not None else None)})
    return out

def tex_escape(v):
    return str(v).replace('_',r'\_').replace('%',r'\%').replace('&',r'\&')

def write_tex_fragments(summary,paired,protocol,fl_data,transfer,sensitivity):
    tex=OUT/'tex'; tex.mkdir(parents=True,exist_ok=True)
    labels={'fixed_low':'Fixed-low','uniform':'Uniform','round_robin':'Round-robin','adaptive':'Adaptive','periodic_full':'Periodic full','fixed_high':'Fixed-high','policy_blind':'Policy-blind'}
    spot={'fixed_low','uniform','round_robin','adaptive','policy_blind'}
    keep=['fixed_low','uniform','round_robin','adaptive','periodic_full','fixed_high','policy_blind']
    lines=[r'\begin{tabular}{llrrrrrr}',r'\toprule',r'Attack & Method & Metric & TDR & CI & MB & Inc. & Spot checks \\',r'\midrule']
    for item in summary:
        if item['method'] not in keep: continue
        is_spot=item['method'] in spot
        metric='record' if is_spot else 'full-scope'
        key='record_level_tdr' if is_spot else 'full_scope_tdr'
        def f(key2,d=3):
            v=item.get(f'{key2}_mean'); return '--' if v is None else f'{v:.{d}f}'
        ci=item.get(f'{key}_95ci'); ci_text='--' if ci is None else f'{ci:.3f}'
        lines.append(f"{tex_escape(item['attack'].title())} & {tex_escape(labels[item['method']])} & {metric} & {f(key)} & {ci_text} & {item['bytes_read_mean']/1e6:.3f} & {item['inconclusive_mean']:.2f} & {item['spot_record_checks_mean']:.0f}\\\\")
    lines += [r'\bottomrule',r'\end{tabular}']; (tex/'budget_summary.tex').write_text('\n'.join(lines)+'\n',encoding='utf8')
    lines=[r'\begin{tabular}{llrrrr}',r'\toprule',r'Workload & Metric & $n$ & Adaptive$-$uniform & 95\% CI low & 95\% CI high \\',r'\midrule']
    for item in paired:
        scale=1e6 if item['metric']=='bytes_read' else 1.0
        label='record-level TDR' if item['metric']=='record_level_tdr' else 'bytes read (MB)'
        lines.append(f"{tex_escape(item['attack'].title())} & {label} & {item['n']} & {item['difference_mean']/scale:.4f} & {item['ci_low']/scale:.4f} & {item['ci_high']/scale:.4f}\\\\")
    lines += [r'\bottomrule',r'\end{tabular}']; (tex/'paired_comparison.tex').write_text('\n'.join(lines)+'\n',encoding='utf8')
    out_labels={'PASS':'P','FAIL_ROSTER':'R','FAIL_POLICY':'Pol','FAIL_RESULT_REPLAY':'Res','INCONCLUSIVE_EVIDENCE':'I'}
    lines=[r'\begin{tabular}{>{\raggedright\arraybackslash}p{0.31\textwidth}ccrrrr}',r'\toprule',r'Case & Spot & Full & Spot B & Full B & Spot upd. & Full upd. \\',r'\midrule']
    for row in protocol['cases']:
        lines.append('{} & {} & {} & {} & {} & {} & {}'.format(tex_escape(row['case'].replace('_',' ')),out_labels[row['record_outcome']],out_labels[row['full_outcome']],row['record_bytes'],row['full_bytes'],row['record_updates_processed'],row['full_updates_processed'])+r'\\')
    lines += [r'\bottomrule',r'\end{tabular}']; (tex/'protocol_matrix.tex').write_text('\n'.join(lines)+'\n',encoding='utf8')
    by_method=defaultdict(list)
    for row in fl_data['runs']: by_method[row['method']].append(row)
    lines=[r'\begin{tabular}{lrrrrrrrr}',r'\toprule',r'Method & F1 & Bal. acc. & Precision & Recall & Train s & Audit s & Audit MB & Max $\Delta$ \\',r'\midrule']; fl_summary=[]
    for method in sorted(by_method):
        group=by_method[method]; item={'method':method}
        for key in ('f1','balanced_accuracy','precision','recall','train_seconds','audit_seconds','total_audit_bytes','max_parameter_difference'):
            item[key]=mean_sd_ci([x[key] for x in group])
        fl_summary.append(item)
        lines.append('{} & {:.4f} & {:.4f} & {:.4f} & {:.4f} & {:.3f} & {:.3f} & {:.3f} & {:.3g}\\\\'.format(tex_escape(method),item['f1'][0],item['balanced_accuracy'][0],item['precision'][0],item['recall'][0],item['train_seconds'][0],item['audit_seconds'][0],item['total_audit_bytes'][0]/1e6,item['max_parameter_difference'][0]))
    lines += [r'\bottomrule',r'\end{tabular}']; (tex/'fl_summary.tex').write_text('\n'.join(lines)+'\n',encoding='utf8'); (OUT/'fl_summary.json').write_text(json.dumps(fl_summary,indent=2),encoding='utf8')
    by_dim=defaultdict(list)
    for row in transfer: by_dim[(int(row['dimension']),row['kind'])].append(row)
    lines=[r'\begin{tabular}{rr rrrr}',r'\toprule',r'Dimension & Type & Payload (bytes) & Payload SD & Wall (ms) & Wall SD \\',r'\midrule']; ts=[]
    for (dim,kind),group in sorted(by_dim.items()):
        payload=mean_sd_ci([float(x['payload_bytes']) for x in group]); wall=mean_sd_ci([float(x['wall_ms']) for x in group]); ts.append({'dimension':dim,'kind':kind,'payload':payload,'wall':wall})
        lines.append(f'{dim} & {kind} & {payload[0]:.0f} & {payload[1]:.1f} & {wall[0]:.3f} & {wall[1]:.3f}'+r'\\')
    lines += [r'\bottomrule',r'\end{tabular}']; (tex/'network_summary.tex').write_text('\n'.join(lines)+'\n',encoding='utf8'); (OUT/'network_summary.json').write_text(json.dumps(ts,indent=2),encoding='utf8')
    if sensitivity:
        lines=[r'\begin{tabular}{rrrrrr}',r'\toprule',r'Budget & Adaptive TDR & Uniform TDR & Adaptive MB & Uniform MB & $n$ \\',r'\midrule']
        for x in sensitivity:
            lines.append(f"{x['budget']} & {x['adaptive_tdr_mean']:.3f}$\\pm${x['adaptive_tdr_95ci']:.3f} & {x['uniform_tdr_mean']:.3f}$\\pm${x['uniform_tdr_95ci']:.3f} & {x['adaptive_bytes_mean']/1e6:.3f}$\\pm${x['adaptive_bytes_95ci']/1e6:.3f} & {x['uniform_bytes_mean']/1e6:.3f}$\\pm${x['uniform_bytes_95ci']/1e6:.3f} & {x['n']}\\\\")
        lines += [r'\bottomrule',r'\end{tabular}']; (tex/'budget_sensitivity.tex').write_text('\n'.join(lines)+'\n',encoding='utf8')

def make_figures(summary,protocol,fl_data,transfer,sensitivity):
    import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
    figdir=OUT/'figures'; figdir.mkdir(parents=True,exist_ok=True)
    index={(x['attack'],x['method']):x for x in summary}; attacks=['random','persistent','withholding']
    colors={'fixed_low':'#9ecae1','uniform':'#4C78A8','round_robin':'#72B7B2','adaptive':'#F58518','periodic_full':'#E45756','fixed_high':'#B279A2','policy_blind':'#54A24B'}
    spot_methods=['fixed_low','uniform','round_robin','adaptive','policy_blind']; full_methods=['periodic_full','fixed_high']
    fig,axes=plt.subplots(1,2,figsize=(12,4),sharey=True)
    for ax,methods,key,title in ((axes[0],spot_methods,'record_level_tdr','Record-level TDR'),(axes[1],full_methods,'full_scope_tdr','Full-scope TDR')):
        x=np.arange(len(attacks)); width=.14
        for j,m in enumerate(methods):
            vals=[index[(a,m)][f'{key}_mean'] or 0 for a in attacks]; cis=[index[(a,m)][f'{key}_95ci'] or 0 for a in attacks]
            ax.bar(x+(j-(len(methods)-1)/2)*width,vals,width,yerr=cis,capsize=2,color=colors[m],label=m.replace('_',' '))
        ax.set_xticks(x,[a.title() for a in attacks]); ax.set_ylim(0,1.05); ax.set_title(title); ax.grid(axis='y',alpha=.25)
    axes[0].set_ylabel('Detection rate'); axes[1].legend(fontsize=8); fig.suptitle('Detection metrics by audit scope (100 seeds; 95% CI)'); fig.tight_layout(); fig.savefig(figdir/'budget_tdr.png',dpi=220,bbox_inches='tight'); plt.close(fig)
    fig,ax=plt.subplots(figsize=(9,4.5)); x=np.arange(len(attacks)); methods=spot_methods+full_methods; width=.1
    for j,m in enumerate(methods): ax.bar(x+(j-(len(methods)-1)/2)*width,[index[(a,m)]['bytes_read_mean']/1e6 for a in attacks],width,label=m.replace('_',' '),color=colors[m])
    ax.set_xticks(x,[a.title() for a in attacks]); ax.set_ylabel('Total bytes read (MB)'); ax.set_title('Serialized evidence traffic under identical attack traces'); ax.legend(ncol=3,fontsize=8); ax.grid(axis='y',alpha=.25); fig.tight_layout(); fig.savefig(figdir/'budget_bytes.png',dpi=220,bbox_inches='tight'); plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,4.5)); methods=[m for m in spot_methods+full_methods if index[('persistent',m)]['detected_latency_n']>0]; vals=[index[('persistent',m)]['first_detection_latency_mean'] for m in methods]; cis=[index[('persistent',m)]['first_detection_latency_95ci'] for m in methods]; ax.bar(range(len(methods)),vals,yerr=cis,color=[colors[m] for m in methods],capsize=3); ax.set_xticks(range(len(methods)),[m.replace('_','\n') for m in methods]); ax.set_ylabel('Rounds from actual attack onset'); ax.set_title('Conditional first-detection latency (censored runs omitted)'); ax.grid(axis='y',alpha=.25); fig.tight_layout(); fig.savefig(figdir/'persistent_latency.png',dpi=220,bbox_inches='tight'); plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,4.5)); methods=spot_methods+full_methods; vals=[index[('withholding',m)]['inconclusive_mean'] or 0 for m in methods]; cis=[index[('withholding',m)]['inconclusive_95ci'] or 0 for m in methods]; ax.bar(range(len(methods)),vals,yerr=cis,color=[colors[m] for m in methods],capsize=3); ax.set_xticks(range(len(methods)),[m.replace('_','\n') for m in methods]); ax.set_ylabel('Inconclusive audit calls'); ax.set_title('Evidence-withholding workload'); ax.grid(axis='y',alpha=.25); fig.tight_layout(); fig.savefig(figdir/'withholding_inconclusive.png',dpi=220,bbox_inches='tight'); plt.close(fig)
    if sensitivity:
        fig,axes=plt.subplots(1,2,figsize=(10,4)); bs=[x['budget'] for x in sensitivity]; axes[0].errorbar(bs,[x['adaptive_tdr_mean'] for x in sensitivity],yerr=[x['adaptive_tdr_95ci'] for x in sensitivity],marker='o',label='Adaptive'); axes[0].errorbar(bs,[x['uniform_tdr_mean'] for x in sensitivity],yerr=[x['uniform_tdr_95ci'] for x in sensitivity],marker='s',label='Uniform'); axes[0].set_xlabel('Spot budget b'); axes[0].set_ylabel('Record-level TDR'); axes[0].grid(alpha=.25); axes[0].legend(); axes[1].errorbar(bs,[x['adaptive_bytes_mean']/1e6 for x in sensitivity],yerr=[x['adaptive_bytes_95ci']/1e6 for x in sensitivity],marker='o',label='Adaptive'); axes[1].errorbar(bs,[x['uniform_bytes_mean']/1e6 for x in sensitivity],yerr=[x['uniform_bytes_95ci']/1e6 for x in sensitivity],marker='s',label='Uniform'); axes[1].set_xlabel('Spot budget b'); axes[1].set_ylabel('Mean bytes read (MB)'); axes[1].grid(alpha=.25); axes[1].legend(); fig.suptitle('Budget sensitivity (equal traces; 40 seeds per budget; 95% CI)'); fig.tight_layout(); fig.savefig(figdir/'budget_sensitivity.png',dpi=220,bbox_inches='tight'); plt.close(fig)
    names=[r['case'].replace('_','\n') for r in protocol['cases']]; fig,ax=plt.subplots(figsize=(13,5)); x=np.arange(len(names)); ax.bar(x-.2,[r['record_bytes'] for r in protocol['cases']],.4,label='Record-level',color='#4C78A8'); ax.bar(x+.2,[r['full_bytes'] for r in protocol['cases']],.4,label='Full replay',color='#E45756'); ax.set_xticks(x,names,fontsize=7); ax.set_ylabel('Network bytes read'); ax.set_title('Protocol attack matrix: bounded spot audit versus full replay'); ax.legend(); ax.grid(axis='y',alpha=.25); fig.tight_layout(); fig.savefig(figdir/'protocol_bytes.png',dpi=220,bbox_inches='tight'); plt.close(fig)
    by=defaultdict(list)
    for row in transfer: by[(int(row['dimension']),row['kind'])].append(row)
    fig,ax=plt.subplots(figsize=(7,4.5))
    for kind,color in (('spot','#4C78A8'),('full','#E45756')):
        dims=sorted({d for d,k in by if k==kind}); means=[]; cis=[]
        for d in dims: m,sd,ci=mean_sd_ci([x['wall_ms'] for x in by[(d,kind)]]); means.append(m); cis.append(ci)
        ax.errorbar(dims,means,yerr=cis,marker='o',capsize=3,label=kind,color=color)
    ax.set_xlabel('Vector dimension'); ax.set_ylabel('TCP transfer wall time (ms)'); ax.set_title('Controlled two-host transfer experiment'); ax.grid(alpha=.25); ax.legend(); fig.tight_layout(); fig.savefig(figdir/'network_transfer.png',dpi=220,bbox_inches='tight'); plt.close(fig)

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    rows,config,provenance=read_budget_rows(); summary=aggregate(rows); paired=paired_comparison(rows)
    protocol=json.loads(PROTOCOL_PATH.read_text(encoding='utf8')); fl_data=json.loads(FL_PATH.read_text(encoding='utf8')); transfer=json.loads(TRANSFER_PATH.read_text(encoding='utf8'))
    sensitivity=json.loads(SENSITIVITY_PATH.read_text(encoding='utf8')) if SENSITIVITY_PATH.exists() else []
    if len(rows)!=2400 or len({int(x['seed']) for x in rows})!=100: raise ValueError('expected corrected 2,400 budget rows and 100 seeds')
    if len(summary)!=24: raise ValueError('expected 3 attacks x 8 methods')
    (OUT/'budget_release_merged.csv').parent.mkdir(parents=True,exist_ok=True)
    with (OUT/'budget_release_merged.csv').open('w',newline='',encoding='utf8') as f:
        w=csv.DictWriter(f,fieldnames=[k for k in rows[0] if k!='audit_outcomes']); w.writeheader(); w.writerows([{k:v for k,v in r.items() if k!='audit_outcomes'} for r in rows])
    (OUT/'budget_release_merged.json').write_text(json.dumps({'status':'corrected measured candidate; observable feedback; latency censoring; pending final review','protocol':'PBA/2','configuration':config,'provenance':provenance,'summary':summary,'paired_comparison':paired,'row_count':len(rows),'seed_count':len({int(x['seed']) for x in rows})},indent=2),encoding='utf8')
    (OUT/'protocol_release.json').write_text(json.dumps(protocol,indent=2),encoding='utf8'); (OUT/'fl_release.json').write_text(json.dumps(fl_data,indent=2),encoding='utf8'); (OUT/'transfer_release.json').write_text(json.dumps(transfer,indent=2),encoding='utf8')
    oracle=evaluate_protocol_oracle(protocol)
    if not oracle['all_match']:
        raise ValueError('independent protocol semantic oracle mismatch')
    (OUT/'protocol_oracle_release.json').write_text(json.dumps(oracle,indent=2),encoding='utf8')
    write_tex_fragments(summary,paired,protocol,fl_data,transfer,sensitivity); make_figures(summary,protocol,fl_data,transfer,sensitivity)
    oracle_script=ROOT/'experiments'/'pba_v2'/'independent_protocol_oracle.py'
    manifest={'generated_on':date.today().isoformat(),'status':'corrected measured candidate; independently reviewable; not a publication-acceptance claim','script_sha256':sha256(Path(__file__)),'independent_oracle_script_sha256':sha256(oracle_script),'inputs':{'budget_partitions':provenance,'protocol':{'path':str(PROTOCOL_PATH),'sha256':sha256(PROTOCOL_PATH)},'fl':{'path':str(FL_PATH),'sha256':sha256(FL_PATH)},'transfer':{'path':str(TRANSFER_PATH),'sha256':sha256(TRANSFER_PATH)},'literature_matrix':{'path':str(LITERATURE_PATH),'sha256':sha256(LITERATURE_PATH)},'sensitivity':({'path':str(SENSITIVITY_PATH),'sha256':sha256(SENSITIVITY_PATH)} if SENSITIVITY_PATH.exists() else None)},'constraints':{'old_cava_modified':False,'four_papers_run_as_performance_baselines':False,'cross_host_timing_ranked':False,'record_level_claims_full_result':False,'adaptive_feedback_ground_truth_free':True,'latency_nondetection_censored':True,'protocol_outcomes_checked_by_independent_semantic_oracle':True},'outputs':[str(p.relative_to(ROOT)) for p in sorted(OUT.rglob('*')) if p.is_file()] + ['experiments/pba_v2/independent_protocol_oracle.py']}
    (OUT/'reproducibility_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    print(json.dumps({'out':str(OUT),'rows':len(rows),'seeds':100,'summary_cells':len(summary),'figures':len(list((OUT/'figures').glob('*.png')))},indent=2))
if __name__=='__main__': main()
