#!/usr/bin/env python3
"""Non-interactive acceptance checks for the PBA/2 release candidate."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
R=ROOT/'experiments'/'pba_v2'/'results'

def check(condition,message):
    if not condition: raise AssertionError(message)

def main():
    # Protocol semantics
    protocol=json.loads((R/'protocol_release_candidate_v3'/'protocol_attack_matrix_final.json').read_text(encoding='utf8'))
    check(len(protocol['cases'])==16,'protocol matrix must have 16 cases')
    p={x['case']:x for x in protocol['cases']}
    check(p['honest_round']['record_outcome']=='PASS' and p['honest_round']['full_outcome']=='PASS','honest case')
    check(not p['honest_round']['record_aggregate_verified'] and p['honest_round']['full_aggregate_verified'],'spot/full aggregate semantics')
    check(p['forged_result']['record_outcome']=='PASS' and p['forged_result']['full_outcome']=='FAIL_RESULT_REPLAY','forged result semantics')
    check(p['missing_evidence']['record_outcome']=='INCONCLUSIVE_EVIDENCE' and p['missing_evidence']['full_outcome']=='INCONCLUSIVE_EVIDENCE','missing evidence semantics')
    check(p['signed_false_declared_count']['record_outcome']=='PASS','signed false declaration boundary')

    # Merged two-host budget release
    budget=json.loads((R/'release_v2'/'budget_release_merged.json').read_text(encoding='utf8'))
    check(budget['row_count']==2400 and budget['seed_count']==100,'budget row/seed count')
    check(budget['configuration']['clients']==30 and budget['configuration']['record_budget']==3,'budget configuration')
    summary={(x['attack'],x['method']):x for x in budget['summary']}
    check(summary[('persistent','adaptive')]['record_level_tdr_mean']>summary[('persistent','uniform')]['record_level_tdr_mean'],'adaptive persistent coverage')
    check(summary[('persistent','fixed_high')]['full_round_tdr_mean']==1.0,'fixed high full replay')
    check(summary[('withholding','uniform')]['inconclusive_mean']>0,'withholding inconclusive')
    check(summary[('persistent','policy_blind')]['record_level_tdr_mean']==0.0,'policy blind does not claim policy detection')

    # Final FL integration
    fl=json.loads((R/'fl_release_candidate_roster_v6.json').read_text(encoding='utf8'))
    check(len(fl['runs'])==15,'FL run count')
    check(set(fl['configuration']['seeds'])=={101,102,103},'FL seed set')
    full=[x for x in fl['rounds'] if x.get('audit') and x['audit']['scope']=='full-round']
    check(full and all(x['audit']['records_processed']==30 and x['audit']['updates_processed']==10 for x in full),'complete roster replay accounting')
    check(all(x['max_parameter_difference']==0.0 for x in fl['runs']),'matched parameter path')
    check(all((x.get('audit') is None or x['audit']['outcome']=='PASS') for x in fl['rounds']),'FL audits pass')

    # Official data manifest and manuscript build
    manifest=json.loads((ROOT/'data'/'unsw_official_subset_v3'/'dataset_manifest.json').read_text(encoding='utf8'))
    check(manifest.get('preprocessing_version')=='PBA2/UNSW-train-only-v2','data preprocessing manifest')
    check(manifest['source_sha256']['train']=='bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa','training checksum')
    check(manifest['source_sha256']['test']=='734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559','testing checksum')
    check((ROOT/'policy_bound_edge_ids_v2.tex').exists(),'manuscript source')
    check((ROOT/'policy_bound_edge_ids_v2.pdf').exists(),'manuscript pdf')
    print(json.dumps({'status':'PASS','protocol_cases':16,'budget_rows':2400,'budget_seeds':100,'fl_runs':15,'fl_full_replays':len(full)}))

if __name__=='__main__': main()
