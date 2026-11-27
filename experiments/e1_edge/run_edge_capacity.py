# -*- coding: utf-8 -*-
"""Paired model-capacity stress test on Edge-IIoTset.

Compares 6,249- and 49,941-parameter MLPs on identical data and client-selection
streams. Protocol, scheduler, withholding and training seeds are held fixed.
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
        _CELL_CACHE[cell_dir] = json.loads(
            (Path(cell_dir) / "client_indices.json").read_text(encoding="utf-8"))
    return _SAMPLE_CACHE[sample_dir], _CELL_CACHE[cell_dir]


def _job(job):
    scenario, method, seed, sample_dir, cell_dir, rounds, dropped, hidden = job
    dropped = tuple(int(x) for x in dropped)
    run_c_consequence.DROPPED_CLIENTS = dropped
    v5_response.DROPPED_CLIENTS = dropped
    v6_bridge.DROPPED_CLIENTS = dropped
    data = _load(sample_dir, cell_dir)
    return v6_bridge.run_cell(
        scenario, method, seed, data, rounds=rounds, hidden=hidden,
        model_seed=seed + 900000, selection_seed=seed + 800000)


def run_grid(data_root: Path, out_root: Path, sample_seeds, partition_seeds, alphas,
             widths, seeds, seed_start, workers, rounds, resume=False):
    out_root.mkdir(parents=True, exist_ok=resume)
    source_paths = [
        Path(__file__).resolve(),
        Path(v6_bridge.__file__).resolve(),
        Path(v5_response.__file__).resolve(),
        Path(run_c_consequence.__file__).resolve(),
    ]
    source_hashes = {str(p): file_hash(p) for p in source_paths}
    for sample_seed in sample_seeds:
        sample_dir = data_root / f"sample_s{sample_seed}"
        sample_manifest = json.loads((sample_dir / "sample_manifest.json").read_text(encoding="utf-8"))
        for partition_seed in partition_seeds:
            for alpha in alphas:
                cell_dir = sample_dir / f"a{alpha}_p{partition_seed}"
                manifest = json.loads((cell_dir / "dataset_manifest.json").read_text(encoding="utf-8"))
                dropped = manifest["dropped_clients"]
                for hidden in widths:
                    params = hidden * (sample_manifest["feature_count"] + 2) + 1
                    out = out_root / f"s{sample_seed}_p{partition_seed}_a{alpha}_h{hidden}"
                    all_jobs = [(s, m, seed, str(sample_dir.resolve()), str(cell_dir.resolve()),
                                 rounds, dropped, hidden)
                                for seed in range(seed_start, seed_start + seeds)
                                for s in SCENARIOS for m in METHODS]
                    cfg = {
                        "corpus": "Edge-IIoTset", "sample_seed": sample_seed,
                        "partition_seed": partition_seed, "alpha": alpha,
                        "data_dir": str(cell_dir.resolve()), "out": str(out.resolve()),
                        "seed_start": seed_start, "seeds": seeds, "rounds": rounds,
                        "budget": 3, "scenarios": list(SCENARIOS), "methods": list(METHODS),
                        "dropped_clients": dropped, "features": sample_manifest["feature_count"],
                        "hidden": hidden, "model_params": params,
                        "train_rows": sample_manifest["rows"]["train"],
                        "test_rows": sample_manifest["rows"]["test"],
                        "client_size_stats": manifest["client_size_stats"],
                        "clients_below_128": manifest["clients_below_128"],
                        "rng_design": "model_seed=training_seed+900000; selection_seed=training_seed+800000",
                        "data_sha256": {
                            "npz": sample_manifest["npz_sha256"],
                            "client_indices": manifest["client_indices_sha256"],
                            "sample_manifest": manifest["sample_manifest_sha256"],
                        },
                        "source_sha256": source_hashes,
                        "numpy_version": np.__version__, "status": "RUNNING",
                    }
                    if resume and out.exists():
                        old_cfg = json.loads((out / "config.json").read_text(encoding="utf-8"))
                        for key in ("sample_seed", "partition_seed", "alpha", "hidden", "model_params",
                                    "seed_start", "seeds", "rounds", "rng_design", "data_sha256"):
                            if old_cfg.get(key) != cfg[key]:
                                raise ValueError(f"resume config mismatch for {out.name}: {key}")
                        rows_path = out / "rows.jsonl"
                        existing = [json.loads(x) for x in rows_path.read_text(encoding="utf-8").splitlines()] \
                            if rows_path.exists() else []
                        done = {(r["scenario"], r["method"], r["seed"]) for r in existing}
                        jobs = [j for j in all_jobs if (j[0], j[1], j[2]) not in done]
                        count = len(existing)
                        mode = "a"
                        if (out / "FAILED.json").exists():
                            (out / "FAILED.json").unlink()
                        if not jobs:
                            summary = analyze(out)
                            print(json.dumps({"cell": out.name, "resume": "complete",
                                              "n_runs": summary["n_runs"]}), flush=True)
                            continue
                    else:
                        out.mkdir(parents=True, exist_ok=False)
                        write_json(out / "config.json", cfg)
                        jobs = all_jobs
                        count = 0
                        mode = "x"
                    try:
                        with (out / "rows.jsonl").open(mode, encoding="utf-8") as ck:
                            with ProcessPoolExecutor(max_workers=workers) as pool:
                                futs = [pool.submit(_job, j) for j in jobs]
                                for fu in as_completed(futs):
                                    row = fu.result()
                                    ck.write(json.dumps(row, separators=(",", ":")) + "\n")
                                    ck.flush()
                                    os.fsync(ck.fileno())
                                    count += 1
                                    if count % 10 == 0 or count == len(all_jobs):
                                        print(json.dumps({"cell": out.name, "completed": count,
                                                          "total": len(all_jobs)}), flush=True)
                    except BaseException as exc:
                        write_json(out / "FAILED.json", {"error": repr(exc), "completed": count,
                                                         "expected": len(jobs)})
                        raise
                    write_json(out / "COMPLETE.json", {"status": "COMPLETED", "completed": count,
                                                       "expected": len(all_jobs)})
                    summary = analyze(out)
                    print(json.dumps({"cell": out.name, "n_runs": summary["n_runs"],
                                      "neutral_f1": summary["means"]["mixed_recovery/neutral"]["f1"]["mean"],
                                      "neutral_applied": summary["means"]["mixed_recovery/neutral"]["applied_violating_rounds"]["mean"],
                                      "audit_MB": summary["means"]["mixed_recovery/neutral"]["audit_total_bytes"]["mean"] / 1e6}),
                          flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-root", type=Path, default=Path(r".\data\edgeiiot_main"))
    p.add_argument("--out-root", type=Path, default=Path(r".\experiments\e1_edge\results_edge_capacity"))
    p.add_argument("--sample-seeds", nargs="+", type=int, default=[101, 102, 103])
    p.add_argument("--partition-seeds", nargs="+", type=int, default=[7, 17, 27])
    p.add_argument("--alphas", nargs="+", type=float, default=[0.5])
    p.add_argument("--widths", nargs="+", type=int, default=[142, 1135])
    p.add_argument("--seeds", type=int, default=10)
    p.add_argument("--seed-start", type=int, default=430001)
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--rounds", type=int, default=60)
    p.add_argument("--resume", action="store_true")
    a = p.parse_args()
    run_grid(a.data_root, a.out_root, a.sample_seeds, a.partition_seeds, a.alphas,
             a.widths, a.seeds, a.seed_start, a.workers, a.rounds, a.resume)


if __name__ == "__main__":
    main()
