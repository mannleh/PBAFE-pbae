# -*- coding: utf-8 -*-
"""E1-L runner on large Edge-IIoTset samples.

Reuses the frozen PBA/3 application machinery unchanged. Data loading is local
to this runner so a large sample NPZ can be shared by many partition cells.
"""
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
from experiments.pba_v3 import v6_bridge, v5_response, run_c_consequence
from experiments.pba_v3.v6_bridge import SCENARIOS, METHODS, analyze
from experiments.pba_v3.v5_common import file_hash, write_json

_SAMPLE_CACHE = {}
_CELL_CACHE = {}


def _load(sample_dir: str, cell_dir: str):
    if sample_dir not in _SAMPLE_CACHE:
        _SAMPLE_CACHE[sample_dir] = np.load(Path(sample_dir) / "unsw_subset.npz")
    if cell_dir not in _CELL_CACHE:
        clients = json.loads((Path(cell_dir) / "client_indices.json").read_text(encoding="utf-8"))
        _CELL_CACHE[cell_dir] = clients
    return _SAMPLE_CACHE[sample_dir], _CELL_CACHE[cell_dir]


def _job(job):
    scenario, method, seed, sample_dir, cell_dir, rounds, dropped, hidden = job
    dropped = tuple(int(x) for x in dropped)
    run_c_consequence.DROPPED_CLIENTS = dropped
    v5_response.DROPPED_CLIENTS = dropped
    v6_bridge.DROPPED_CLIENTS = dropped
    data = _load(sample_dir, cell_dir)
    return v6_bridge.run_cell(scenario, method, seed, data, rounds=rounds, hidden=hidden)


def run_cell_grid(data_root: Path, out_root: Path, sample_seeds, partition_seeds, alphas,
                  seeds, seed_start, workers, rounds, hidden):
    out_root.mkdir(parents=True, exist_ok=False)
    for sample_seed in sample_seeds:
        sample_dir = data_root / f"sample_s{sample_seed}"
        sample_manifest = json.loads((sample_dir / "sample_manifest.json").read_text(encoding="utf-8"))
        for partition_seed in partition_seeds:
            for alpha in alphas:
                cell_dir = sample_dir / f"a{alpha}_p{partition_seed}"
                manifest = json.loads((cell_dir / "dataset_manifest.json").read_text(encoding="utf-8"))
                dropped = manifest["dropped_clients"]
                out = out_root / f"s{sample_seed}_p{partition_seed}_a{alpha}"
                out.mkdir(parents=True, exist_ok=False)
                cfg = {
                    "corpus": "Edge-IIoTset", "sample_seed": sample_seed,
                    "partition_seed": partition_seed, "alpha": alpha,
                    "data_dir": str(cell_dir.resolve()), "out": str(out.resolve()),
                    "seed_start": seed_start, "seeds": seeds, "rounds": rounds,
                    "budget": 3, "scenarios": list(SCENARIOS), "methods": list(METHODS),
                    "dropped_clients": dropped, "features": sample_manifest["feature_count"],
                    "hidden": hidden, "model_params": hidden * (sample_manifest["feature_count"] + 2) + 1,
                    "train_rows": sample_manifest["rows"]["train"],
                    "test_rows": sample_manifest["rows"]["test"],
                    "client_size_stats": manifest["client_size_stats"],
                    "clients_below_128": manifest["clients_below_128"],
                    "data_sha256": {
                        "npz": sample_manifest["npz_sha256"],
                        "client_indices": manifest["client_indices_sha256"],
                        "sample_manifest": manifest["sample_manifest_sha256"],
                    },
                    "numpy_version": np.__version__, "status": "RUNNING",
                }
                write_json(out / "config.json", cfg)
                jobs = [(s, m, seed, str(sample_dir.resolve()), str(cell_dir.resolve()), rounds, dropped, hidden)
                        for seed in range(seed_start, seed_start + seeds)
                        for s in SCENARIOS for m in METHODS]
                count = 0
                try:
                    with (out / "rows.jsonl").open("x", encoding="utf-8") as ck:
                        with ProcessPoolExecutor(max_workers=workers) as pool:
                            futs = [pool.submit(_job, j) for j in jobs]
                            for fu in as_completed(futs):
                                row = fu.result()
                                ck.write(json.dumps(row, separators=(",", ":")) + "\n")
                                ck.flush()
                                os.fsync(ck.fileno())
                                count += 1
                                if count % 10 == 0 or count == len(jobs):
                                    print(json.dumps({"cell": out.name, "completed": count,
                                                      "total": len(jobs)}), flush=True)
                except BaseException as exc:
                    write_json(out / "FAILED.json", {"error": repr(exc), "completed": count,
                                                     "expected": len(jobs)})
                    raise
                write_json(out / "COMPLETE.json", {"status": "COMPLETED", "completed": count,
                                                   "expected": len(jobs)})
                summary = analyze(out)
                print(json.dumps({"cell": out.name, "n_runs": summary["n_runs"],
                                  "neutral_f1": summary["means"]["mixed_recovery/neutral"]["f1"]["mean"],
                                  "neutral_applied": summary["means"]["mixed_recovery/neutral"]["applied_violating_rounds"]["mean"]}),
                      flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-root", type=Path, default=Path(r".\data\edgeiiot_large"))
    p.add_argument("--out-root", type=Path, default=Path(r".\experiments\e1_edge\results_large_pilot"))
    p.add_argument("--sample-seeds", nargs="+", type=int, default=[101, 102])
    p.add_argument("--partition-seeds", nargs="+", type=int, default=[7, 17])
    p.add_argument("--alphas", nargs="+", type=float, default=[0.1, 0.5, 1.0])
    p.add_argument("--seeds", type=int, default=5)
    p.add_argument("--seed-start", type=int, default=410001)
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--rounds", type=int, default=60)
    p.add_argument("--hidden", type=int, default=142)
    a = p.parse_args()
    run_cell_grid(a.data_root, a.out_root, a.sample_seeds, a.partition_seeds, a.alphas,
                  a.seeds, a.seed_start, a.workers, a.rounds, a.hidden)


if __name__ == "__main__":
    main()
