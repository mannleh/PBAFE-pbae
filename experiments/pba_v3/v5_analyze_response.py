"""Paired seed analysis of the no-oracle response experiment; no row selection."""
import argparse
import json
from pathlib import Path
from .v5_common import bootstrap, write_json
from .v5_response import ARMS

TOTAL_KEYS = ("attack_rounds", "attacked_updates_applied", "prevented_bad_rounds",
              "honest_rounds_rejected", "rejected_rounds", "audit_total_bytes",
              "audit_cpu_ms", "local_training_steps", "local_rows_processed",
              "discarded_training_steps", "discarded_rows_processed", "full_audit_calls",
              "actual_replays", "application_upload_payload_bytes",
              "application_download_payload_bytes", "candidate_download_payload_bytes")


def analyze(root):
    complete = json.loads((root/"COMPLETE.json").read_text())
    config = json.loads((root/"config.json").read_text())
    rows = [json.loads(line) for line in (root/"rows.jsonl").read_text().splitlines()]
    assert complete["completed"] == complete["expected"] == len(rows)
    seed_ids = list(range(config["seed_start"],config["seed_start"]+config["seeds"]))
    groups={arm: sorted([r for r in rows if r["arm"]==arm],key=lambda r:r["seed"]) for arm in ARMS}
    means={}
    for arm,part in groups.items():
        assert [r["seed"] for r in part] == seed_ids
        means[arm]={key:bootstrap([r["totals"][key] for r in part]) for key in TOTAL_KEYS}
        for metric in ("f1","balanced_accuracy","precision","recall"):
            means[arm][metric]=bootstrap([r["final"][metric] for r in part])
        avoided=sum(r["totals"]["prevented_bad_rounds"] for r in part)
        means[arm]["audit_bytes_per_prevented_bad_round"]=sum(r["totals"]["audit_total_bytes"] for r in part)/avoided if avoided else None
    comparisons=[("clean_noaudit","drop_noaudit"),
                 ("drop_uniform_b3","drop_noaudit"),("drop_neutral_b3","drop_noaudit"),
                 ("drop_separated_b3","drop_noaudit"),("drop_full_b30","drop_noaudit"),
                 ("drop_neutral_b3","drop_uniform_b3"),("drop_neutral_b3","drop_separated_b3")]
    paired={}
    for left,right in comparisons:
        a,b=groups[left],groups[right]
        out={}
        for key in ("f1","balanced_accuracy"):
            differences=[x["final"][key]-y["final"][key] for x,y in zip(a,b)]
            out[key]=bootstrap(differences)
            if right=="drop_noaudit" and left in ("drop_uniform_b3","drop_neutral_b3") and key=="f1":
                out["primary_f1_ci97_5"]=bootstrap(differences,level=.975)
        for key in TOTAL_KEYS:
            out[key]=bootstrap([x["totals"][key]-y["totals"][key] for x,y in zip(a,b)])
        paired[left+"-"+right]=out
    for seed in seed_ids:
        part=[r for r in rows if r["seed"]==seed]
        assert len(set(r["initial_model_sha256"] for r in part))==1
        assert len(set(r["selection_schedule_sha256"] for r in part))==1
    summary={"means":means,"paired":paired,"n_seeds":len(seed_ids),"n_runs":len(rows),
             "ci_unit":"training seed conditional on fixed data split and fixed client partition",
             "ci_method":"paired seed percentile bootstrap, 20000 resamples",
             "scope":"bounded UNSW-NB15 subset; no recovery oracle; response rejects and retains"}
    write_json(root/"summary.json",summary)
    return summary


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    a=p.parse_args()
    s=analyze(a.root)
    print(json.dumps({"n_runs":s["n_runs"],"means":{k:{x:v[x]["mean"] for x in ("f1","attacked_updates_applied","audit_total_bytes")} for k,v in s["means"].items()}}))
