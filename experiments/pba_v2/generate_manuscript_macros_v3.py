#!/usr/bin/env python3
import json
from pathlib import Path
HERE=Path(__file__).resolve().parent; OUT=HERE/'results'/'release_v3'
def item(d,a,m):
    return next(x for x in d['summary'] if x['attack']==a and x['method']==m)
def fmt(v,d=3): return '--' if v is None else f'{float(v):.{d}f}'
def main():
    budget=json.loads((OUT/'budget_release_merged.json').read_text(encoding='utf8'))
    fl=json.loads((OUT/'fl_summary.json').read_text(encoding='utf8'))
    net=json.loads((OUT/'network_summary.json').read_text(encoding='utf8'))
    pa=item(budget,'persistent','adaptive'); pu=item(budget,'persistent','uniform'); pp=item(budget,'persistent','periodic_full'); pf=item(budget,'persistent','fixed_high'); pr=item(budget,'random','adaptive'); pw=item(budget,'withholding','uniform')
    flm={x['method']:x for x in fl}; t={(x['dimension'],x['kind']):x for x in net}
    b=OUT/'tex'/'result_macros.tex'; b.parent.mkdir(parents=True,exist_ok=True)
    lines=['% Auto-generated from corrected release_v3 artifacts; do not edit.',
      r'\newcommand{\PBASeedCount}{100}',r'\newcommand{\PBARecordBudget}{3}',
      r'\newcommand{\PBAAdaptivePersistentTDR}{'+fmt(pa['record_level_tdr_mean'])+'}',
      r'\newcommand{\PBAUniformPersistentTDR}{'+fmt(pu['record_level_tdr_mean'])+'}',
      r'\newcommand{\PBAPeriodicPersistentTDR}{'+fmt(pp['full_scope_tdr_mean'])+'}',
      r'\newcommand{\PBAFullHighPersistentTDR}{'+fmt(pf['full_scope_tdr_mean'])+'}',
      r'\newcommand{\PBAAdaptivePersistentBytes}{'+str(round(pa['bytes_read_mean']))+'}',
      r'\newcommand{\PBAUniformPersistentBytes}{'+str(round(pu['bytes_read_mean']))+'}',
      r'\newcommand{\PBAPeriodicPersistentBytes}{'+str(round(pp['bytes_read_mean']))+'}',
      r'\newcommand{\PBAFullHighPersistentBytes}{'+str(round(pf['bytes_read_mean']))+'}',
      r'\newcommand{\PBAAdaptiveRandomTDR}{'+fmt(pr['record_level_tdr_mean'])+'}',
      r'\newcommand{\PBAWithholdingUniformInconclusive}{'+fmt(pw['inconclusive_mean'],2)+'}',
      r'\newcommand{\PBAAdaptivePersistentCoverage}{'+fmt(pa['attack_coverage_mean'])+'}',
      r'\newcommand{\PBAUniformPersistentCoverage}{'+fmt(pu['attack_coverage_mean'])+'}',
      r'\newcommand{\PBAAdaptiveLatencyDetected}{'+fmt(pa['first_detection_observed_mean'],3)+'}',
      r'\newcommand{\PBAUniformLatencyDetected}{'+fmt(pu['first_detection_observed_mean'],3)+'}',
      r'\newcommand{\PBAFLSeedCount}{3}',
      r'\newcommand{\PBAFOne}{'+fmt(flm['fedavg_no_audit']['f1'][0],4)+'}',
      r'\newcommand{\PBAFOneSD}{'+fmt(flm['fedavg_no_audit']['f1'][1],4)+'}',
      r'\newcommand{\PBAFBalancedAccuracy}{'+fmt(flm['fedavg_no_audit']['balanced_accuracy'][0],4)+'}',
      r'\newcommand{\PBAFBalancedAccuracySD}{'+fmt(flm['fedavg_no_audit']['balanced_accuracy'][1],4)+'}',
      r'\newcommand{\PBAFPrecision}{'+fmt(flm['fedavg_no_audit']['precision'][0],4)+'}',
      r'\newcommand{\PBAFRecall}{'+fmt(flm['fedavg_no_audit']['recall'][0],4)+'}',
      r'\newcommand{\PBAFTrainSeconds}{'+fmt(flm['fedavg_no_audit']['train_seconds'][0],3)+'}',
      r'\newcommand{\PBAFAuditSeconds}{'+fmt(flm['audit_enabled']['audit_seconds'][0],3)+'}',
      r'\newcommand{\PBAFAuditBytes}{'+fmt(flm['audit_enabled']['total_audit_bytes'][0]/1e6,3)+'}',
      r'\newcommand{\PBAAuditMaxParamDiff}{0}',
      r'\newcommand{\PBASpotBytesDim}{'+str(round(t[(256,'spot')]['payload'][0]))+'}',
      r'\newcommand{\PBAFullBytesDim}{'+str(round(t[(256,'full')]['payload'][0]))+'}',
      r'\newcommand{\PBASpotWallDim}{'+fmt(t[(256,'spot')]['wall'][0],3)+'}',
      r'\newcommand{\PBAFullWallDim}{'+fmt(t[(256,'full')]['wall'][0],3)+'}',
    ]
    b.write_text('\n'.join(lines)+'\n',encoding='utf8'); print(b)
if __name__=='__main__': main()
