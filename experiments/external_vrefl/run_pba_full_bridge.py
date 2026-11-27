# -*- coding: utf-8 -*-
"""PBA/3 full-scope control on the same bridge fixture as VREFL-full."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

for _n in ("OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "OMP_NUM_THREADS"):
    os.environ[_n] = "1"
sys.path.insert(0, r".")
import numpy as np
from experiments.pba_v3 import v6_bridge
from experiments.pba_v3.run_c_consequence import load
from experiments.pba_v3.v5_common import file_hash, write_json

_CACHE = {}


def _job(job):
    scenario, seed, data_dir, rounds = job
    if data_dir not in _CACHE:
        _CACHE[data_dir] = load(data_dir)
    row = v6_bridge.run_cell(scenario, "uniform", seed, _CACHE[data_dir],
                             rounds=rounds, hidden=32, full=True)
    row["method"] = "pba_full"
    return row


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", type=Path, default=Path(r".\data\unsw_official_subset_v3"))
    p.add_argument("--out", type=Path, default=Path(r".\experiments\external_vrefl\results_pba_full"))
    p.add_argument("--seeds", type=int, default=20)
    p.add_argument("--seed-start", type=int, default=310001)
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--rounds", type=int, default=60)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    write_json(a.out / "config.json", {
        "baseline": "PBA/3 full scope", "data_dir": str(a.data_dir.resolve()),
        "out": str(a.out.resolve()), "seed_start": a.seed_start, "seeds": a.seeds,
        "rounds": a.rounds, "scenarios": ["mixed_recovery", "withholding_recovery"],
        "methods": ["pba_full"], "source_sha256": {str(Path(v6_bridge.__file__).resolve()): file_hash(Path(v6_bridge.__file__))},
        "data_sha256": {n: file_hash(a.data_dir / n) for n in ("unsw_subset.npz", "client_indices.json")},
        "numpy_version": np.__version__, "status": "RUNNING",
    })
    jobs = [(scenario, seed, str(a.data_dir.resolve()), a.rounds)
            for seed in range(a.seed_start, a.seed_start + a.seeds)
            for scenario in ("mixed_recovery", "withholding_recovery")]
    count = 0
    try:
        with (a.out / "rows.jsonl").open("x", encoding="utf-8") as ck:
            with ProcessPoolExecutor(max_workers=a.workers) as pool:
                futs = [pool.submit(_job, j) for j in jobs]
                for fu in as_completed(futs):
                    row = fu.result()
                    ck.write(json.dumps(row, separators=(",", ":")) + "\n")
                    ck.flush()
                    os.fsync(ck.fileno())
                    count += 1
                    print(json.dumps({"completed": count, "total": len(jobs),
                                      "scenario": row["scenario"], "seed": row["seed"],
                                      "f1": row["final"]["f1"],
                                      "applied": row["bridge"]["applied_violating_rounds"]}), flush=True)
    except BaseException as exc:
        write_json(a.out / "FAILED.json", {"error": repr(exc), "completed": count,
                                           "expected": len(jobs)})
        raise
    write_json(a.out / "COMPLETE.json", {"status": "COMPLETED", "completed": count,
                                         "expected": len(jobs)})


if __name__ == "__main__":
    main()
