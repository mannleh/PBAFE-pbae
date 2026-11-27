#!/usr/bin/env python3
"""Generate the PBA/2 protocol attack matrix from authenticated fixtures."""
import argparse, csv, json
from pathlib import Path
from .repository import make_fixture, tamper
from .verify import audit

CASES = ("honest_round", "update_replacement", "unsigned_insertion", "identity_exchange",
         "duplicate_record", "roster_omission", "unannounced_client", "modified_declared_count",
         "signed_false_declared_count", "rule_substitution", "weight_inconsistency", "forged_result",
         "missing_evidence", "old_round_replay", "forged_bulletin", "forged_result_plus_missing_opening")

def case_fixture(case):
    f = make_fixture(clients=10, dimension=8, seed=20260915)
    if case == "signed_false_declared_count":
        return tamper(f, case, (0,))
    if case == "forged_result_plus_missing_opening":
        f = tamper(f, "forged_result", (0,))
        return tamper(f, "missing_evidence", (0,))
    if case == "honest_round":
        return f
    return tamper(f, case, (0,))

def run(out):
    rows=[]
    for case in CASES:
        f=case_fixture(case); spot=audit(f.source,f.trust,slots=[0]); full=audit(f.source,f.trust,full=True)
        rows.append({"case":case,"record_outcome":spot.outcome,"full_outcome":full.outcome,
                     "record_aggregate_verified":spot.aggregate_verified,"full_aggregate_verified":full.aggregate_verified,
                     "record_bytes":spot.total_network_bytes,"full_bytes":full.total_network_bytes,
                     "record_processed":spot.records_processed,"full_processed":full.records_processed,
                     "record_updates_processed":spot.updates_processed,"full_updates_processed":full.updates_processed,
                     "record_inconclusive":spot.inconclusive_reason,"full_inconclusive":full.inconclusive_reason,
                     "record_findings":spot.findings,"full_findings":full.findings})
    out.mkdir(parents=True,exist_ok=True)
    with (out/"protocol_attack_matrix_final.csv").open("w",newline="",encoding="utf8") as h:
        w=csv.DictWriter(h,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    (out/"protocol_attack_matrix_final.json").write_text(json.dumps({"protocol":"PBA/2","cases":rows},indent=2),encoding="utf8")
    print(json.dumps({"cases":len(rows),"out":str(out)},indent=2))

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--out",type=Path,required=True); a=p.parse_args(); run(a.out)
