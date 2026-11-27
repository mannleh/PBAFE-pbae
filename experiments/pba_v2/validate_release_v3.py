#!/usr/bin/env python3
"""Independent acceptance checks for the corrected PBA/2 release."""
import argparse,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; R=ROOT/'experiments'/'pba_v2'/'results'
def check(c,m):
    if not c: raise AssertionError(m)
def sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()
def main():
    parser=argparse.ArgumentParser(description='Validate the PBA/2 release and a specified final PDF.')
    parser.add_argument('--pdf',type=Path,default=ROOT/'submission_pba2_final_2026-09-28'/'policy_bound_edge_ids_v2.pdf')
    args=parser.parse_args()
    protocol=json.loads((R/'protocol_final_v4'/'protocol_attack_matrix_final.json').read_text(encoding='utf8')); p={x['case']:x for x in protocol['cases']}
    check(len(protocol['cases'])==16,'protocol case count')
    check('forged_result_plus_missing_opening' in p,'descriptive combined-failure case')
    check(p['honest_round']['record_outcome']=='PASS' and p['honest_round']['full_outcome']=='PASS','honest semantics')
    check(not p['honest_round']['record_aggregate_verified'] and p['honest_round']['full_aggregate_verified'],'spot/full aggregate scope')
    check(p['forged_result']['record_outcome']=='PASS' and p['forged_result']['full_outcome']=='FAIL_RESULT_REPLAY','result replay semantics')
    check(p['missing_evidence']['record_outcome']=='INCONCLUSIVE_EVIDENCE' and p['missing_evidence']['full_outcome']=='INCONCLUSIVE_EVIDENCE','missing evidence semantics')
    check(p['signed_false_declared_count']['record_outcome']=='PASS' and p['signed_false_declared_count']['full_outcome']=='PASS','declaration boundary')
    oracle=json.loads((R/'release_v3'/'protocol_oracle_release.json').read_text(encoding='utf8'))
    check(oracle.get('all_match') is True and oracle.get('case_count')==16 and oracle.get('expected_case_count')==16,'independent semantic oracle')
    budget=json.loads((R/'release_v3'/'budget_release_merged.json').read_text(encoding='utf8'))
    c=budget['configuration']; check(budget['row_count']==2400 and budget['seed_count']==100,'budget rows/seeds')
    check(c['clients']==30 and c['record_budget']==3,'budget config')
    check(c['adaptive_feedback']=='verifier.record_outcomes_only','no oracle feedback')
    check(c['latency']=='actual_attack_onset; nondetection_censored','latency definition')
    check(all(k in c['metric_definitions'] for k in ('record_level_tdr','full_scope_tdr','full_replay_result_tdr','attack_coverage')),'metric definitions')
    summary={(x['attack'],x['method']):x for x in budget['summary']}
    check(summary[('persistent','adaptive')]['detected_latency_n']+summary[('persistent','adaptive')]['latency_censored_n']==100,'latency censoring accounting')
    check(summary[('persistent','fixed_high')]['full_scope_tdr_mean']==1.0,'fixed high full scope')
    check(summary[('withholding','uniform')]['inconclusive_mean']>0,'withholding inconclusive')
    check(summary[('persistent','policy_blind')]['record_level_tdr_mean']==0.0,'policy blind boundary')
    sens=json.loads((R/'final_budget_sensitivity'/'sensitivity_summary.json').read_text(encoding='utf8'))
    check([x['budget'] for x in sens]==[1,5,10],'budget sensitivity budgets')
    check(all(x['n']==40 for x in sens),'budget sensitivity seeds')
    fl=json.loads((R/'fl_release_candidate_roster_v6.json').read_text(encoding='utf8'))
    check(len(fl['runs'])==15 and set(fl['configuration']['seeds'])=={101,102,103},'FL runs')
    full=[x for x in fl['rounds'] if x.get('audit') and x['audit']['scope']=='full-round']
    check(full and all(x['audit']['records_processed']==30 and x['audit']['updates_processed']==10 for x in full),'FL full replay accounting')
    check(all(x['max_parameter_difference']==0.0 for x in fl['runs']),'matched parameter path')
    manifest=json.loads((ROOT/'data'/'unsw_official_subset_v3'/'dataset_manifest.json').read_text(encoding='utf8'))
    check(manifest.get('preprocessing_version')=='PBA2/UNSW-train-only-v2','dataset preprocessing')
    final_pdf=args.pdf.resolve(); check(final_pdf.exists() and final_pdf.stat().st_size>0,'final submission pdf')
    source=final_pdf.with_suffix('.tex'); check(source.exists(),'source accompanying final submission pdf')
    tex=source.read_text(encoding='utf8')
    cites=set(k for group in re.findall(r'\\cite\{([^}]+)\}',tex) for k in group.split(','))
    bib=set(re.findall(r'\\bibitem\{([^}]+)\}',tex))
    for name in re.findall(r'\\bibliography\{([^}]+)\}',tex):
        for entry in name.split(','):
            bib_path=source.parent/(entry.strip()+'.bib')
            check(bib_path.exists(),'bibliography accompanying manuscript: '+str(bib_path))
            bib.update(re.findall(r'@\w+\s*\{\s*([^,\s]+)\s*,',bib_path.read_text(encoding='utf8')))
    check(cites<=bib,'all citation keys have bibliography entries')
    print(json.dumps({'status':'PASS','protocol_cases':len(protocol['cases']),'budget_rows':budget['row_count'],'budget_seeds':budget['seed_count'],'sensitivity_budgets':[x['budget'] for x in sens],'fl_runs':len(fl['runs']),'fl_full_replays':len(full),'pdf':str(final_pdf),'pdf_sha256':sha256(final_pdf)},indent=2))
if __name__=='__main__': main()
