"""Limited exact rerun check; no claim of rerunning the full study."""
import os
for name in ("OPENBLAS_NUM_THREADS","MKL_NUM_THREADS","OMP_NUM_THREADS"):
    os.environ.setdefault(name,"1")
import argparse
import json
from pathlib import Path
from .v5_scheduler import run_seed
from .v5_response import run_arm, load
from .v5_common import write_json

TIMING={"cpu_ms","audit_cpu_ms","audit_wall_ms","training_wall_ms","evidence_build_wall_ms"}


def non_timing(obj):
    if isinstance(obj,dict):
        return {str(k):non_timing(v) for k,v in obj.items() if k not in TIMING}
    if isinstance(obj,list):
        return [non_timing(v) for v in obj]
    return obj


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    a=p.parse_args()
    out=a.root/"limited_reproduction.json"
    if out.exists(): raise FileExistsError(out)
    old=json.loads((a.root/"scheduler"/"seed_220001.json").read_text())
    new=run_seed(220001)
    assert non_timing(old)==non_timing(new),"scheduler rerun mismatch"
    print("Scheduler seed220001 all28 cells match exactly excluding timing",flush=True)
    rows=[json.loads(line) for line in (a.root/"response"/"rows.jsonl").read_text().splitlines()]
    old=next(r for r in rows if r["seed"]==300001 and r["arm"]=="drop_neutral_b3")
    new=run_arm("drop_neutral_b3",300001,load("data/unsw_official_subset_v3"))
    assert non_timing(old)==non_timing(new),"response rerun mismatch"
    write_json(out,{"status":"PASS","scheduler":{"seed":220001,"cells":28,"rounds_per_cell":60},
                    "response":{"seed":300001,"arm":"drop_neutral_b3","rounds":60},
                    "match":"exact all fields except measured timing","full_study_rerun":False})
    print("Response seed300001 neutral b3 exact match excluding timing",flush=True)

if __name__=="__main__": main()
