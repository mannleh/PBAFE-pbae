"""Bounded deterministic rerun of the first evaluation seed, neutral, both scenarios."""
import argparse
import hashlib
import json
import os
from pathlib import Path
for name in ("OPENBLAS_NUM_THREADS","MKL_NUM_THREADS","OMP_NUM_THREADS"):
    os.environ[name]="1"
from .v6_bridge import run_cell, SCENARIOS
from .run_c_consequence import load


def normalize(row):
    row=json.loads(json.dumps(row))
    row["totals"]={k:v for k,v in row["totals"].items() if not k.endswith("_ms")}
    return row


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    a=p.parse_args()
    cfg=json.loads((a.root/"config.json").read_text())
    stored=[json.loads(x) for x in (a.root/"rows.jsonl").read_text().splitlines()]
    for name,want in cfg["source_sha256"].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest()!=want:
            raise ValueError("source changed: "+name)
    data=load(cfg["data_dir"])
    comparisons=[]
    for scenario in SCENARIOS:
        original=next(r for r in stored if (r["scenario"],r["method"],r["seed"])==(scenario,"neutral",cfg["seed_start"]))
        rerun=run_cell(scenario,"neutral",cfg["seed_start"],data,rounds=cfg["rounds"])
        equal=normalize(original)==normalize(rerun)
        comparisons.append(dict(scenario=scenario,method="neutral",seed=cfg["seed_start"],exact_non_timing_match=equal))
    result=dict(status="PASS" if all(x["exact_non_timing_match"] for x in comparisons) else "FAIL",
                scope="first evaluation seed, neutral, two scenarios; same implementation, not full reproduction",
                excluded="local wall/CPU timing fields only",comparisons=comparisons)
    (a.root/"reproduction.json").write_text(json.dumps(result,indent=2),encoding="utf8")
    print(json.dumps(result))
    if result["status"]!="PASS":raise SystemExit(1)

if __name__=="__main__":main()
