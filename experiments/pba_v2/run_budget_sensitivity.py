from pathlib import Path
import subprocess, sys, json
root=Path(__file__).resolve().parents[2]
out_root=root/'experiments'/'pba_v2'/'results'/'final_budget_sensitivity'
out_root.mkdir(parents=True,exist_ok=True)
# 40 seeds per budget, split into two independent 20-seed partitions.
for budget in (1,5,10):
    for label,start in (('a',0),('b',20)):
        out=out_root/f'b{budget}_{label}'
        cmd=[sys.executable,'-m','experiments.pba_v2.run_budget_v3','--out',str(out),'--seeds','20','--seed-start',str(start),'--budget',str(budget)]
        print('RUN',budget,label,flush=True)
        subprocess.run(cmd,cwd=root,check=True)
# Aggregate only persistent attack and the two spot methods for the sensitivity figure.
rows=[]
for budget in (1,5,10):
    part=[]
    for label in ('a','b'):
        data=json.loads((out_root/f'b{budget}_{label}'/'budget_audit_results_release.json').read_text(encoding='utf8'))
        part += [r for r in data['rows'] if r['attack']=='persistent' and r['method'] in ('adaptive','uniform')]
    for method in ('adaptive','uniform'):
        group=[r for r in part if r['method']==method]
        def mean(k): return sum(float(r[k]) for r in group)/len(group)
        def ci(k):
            import statistics, math
            vals=[float(r[k]) for r in group]
            return 1.96*(statistics.stdev(vals)/math.sqrt(len(vals))) if len(vals)>1 else 0.0
        rows.append({'budget':budget,'method':method,'tdr_mean':mean('record_level_tdr'),'tdr_95ci':ci('record_level_tdr'),'bytes_mean':mean('bytes_read'),'bytes_95ci':ci('bytes_read'),'n':len(group)})
summary=[]
for budget in (1,5,10):
    a=next(x for x in rows if x['budget']==budget and x['method']=='adaptive')
    u=next(x for x in rows if x['budget']==budget and x['method']=='uniform')
    summary.append({'budget':budget,'adaptive_tdr_mean':a['tdr_mean'],'adaptive_tdr_95ci':a['tdr_95ci'],'uniform_tdr_mean':u['tdr_mean'],'uniform_tdr_95ci':u['tdr_95ci'],'adaptive_bytes_mean':a['bytes_mean'],'adaptive_bytes_95ci':a['bytes_95ci'],'uniform_bytes_mean':u['bytes_mean'],'uniform_bytes_95ci':u['bytes_95ci'],'n':a['n']})
(out_root/'sensitivity_summary.json').write_text(json.dumps(summary,indent=2),encoding='utf8')
print(json.dumps(summary,indent=2))
