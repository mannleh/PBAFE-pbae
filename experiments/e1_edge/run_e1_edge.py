# -*- coding: utf-8 -*-
"""E1 cross-dataset application experiment on Edge-IIoTset.

Reuses the FROZEN PBA/3 application machinery (v6_bridge.run_cell: learning,
aggregation, audit, scheduler, reject-and-retain) without modifying it. The only
dataset-specific override is DROPPED_CLIENTS (the drop_client attack targets),
re-derived per Dirichlet partition by prepare_edgeiiot.py and injected into the
three modules that read it. Analysis is delegated to v6_bridge.analyze so the
reported contrasts/CIs use exactly the paper's matched-seed bootstrap method.

Run:  python -m experiments.e1_edge.run_e1_edge --seeds 20 --workers 6
"""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

for _n in ("OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "OMP_NUM_THREADS"):
    os.environ[_n] = "1"
sys.path.insert(0, r".")
import numpy as np
from experiments.pba_v3 import v6_bridge, v5_response, run_c_consequence
from experiments.pba_v3.v6_bridge import SCENARIOS, METHODS, analyze
from experiments.pba_v3.v5_common import file_hash, write_json

_CACHE = {}


def _e1_job(job):
    scenario, method, seed, data_dir, rounds, dropped, hidden = job
    dropped = tuple(int(x) for x in dropped)
    # Inject the re-derived attack targets into every module that reads them.
    run_c_consequence.DROPPED_CLIENTS = dropped   # manipulate_states
    v5_response.DROPPED_CLIENTS = dropped         # published_aggregate
    v6_bridge.DROPPED_CLIENTS = dropped           # run_cell + withholding_slots
    if data_dir not in _CACHE:
        _CACHE[data_dir] = run_c_consequence.load(data_dir)
    return v6_bridge.run_cell(scenario, method, seed, _CACHE[data_dir], rounds=rounds,
                              hidden=hidden)


def run_alpha(alpha, data_root, out_root, seeds, seed_start, workers, rounds, hidden=32):
    data_dir = Path(data_root) / f"edgeiiot_a{alpha}"
    manifest = json.loads((data_dir / "dataset_manifest.json").read_text(encoding="utf-8"))
    dropped = manifest["dropped_clients"]
    out = Path(out_root) / f"e1_edge_a{alpha}"
    out.mkdir(parents=True, exist_ok=False)
    cfg = {"alpha": alpha, "data_dir": str(data_dir.resolve()), "out": str(out.resolve()),
           "seed_start": seed_start, "seeds": seeds, "rounds": rounds, "budget": 3,
           "scenarios": list(SCENARIOS), "methods": list(METHODS),
           "dropped_clients": dropped, "corpus": "Edge-IIoTset",
           "features": manifest["features"], "hidden": hidden,
           "model_params": hidden * (manifest["features"] + 2) + 1,
           "status": "RUNNING",
           "data_sha256": {n: file_hash(data_dir / n) for n in ("unsw_subset.npz", "client_indices.json")},
           "numpy_version": np.__version__}
    write_json(out / "config.json", cfg)
    jobs = [(s, m, seed, str(data_dir.resolve()), rounds, dropped, hidden)
            for seed in range(seed_start, seed_start + seeds) for s in SCENARIOS for m in METHODS]
    count = 0
    try:
        with (out / "rows.jsonl").open("x", encoding="utf-8") as ck:
            with ProcessPoolExecutor(max_workers=workers) as pool:
                futs = [pool.submit(_e1_job, j) for j in jobs]
                for fu in as_completed(futs):
                    row = fu.result()
                    ck.write(json.dumps(row, separators=(",", ":")) + "\n"); ck.flush(); os.fsync(ck.fileno())
                    count += 1
                    if count % 20 == 0 or count == len(jobs):
                        print(json.dumps({"alpha": alpha, "completed": count, "total": len(jobs)}), flush=True)
    except BaseException as exc:
        write_json(out / "FAILED.json", {"error": repr(exc), "completed": count, "expected": len(jobs)})
        raise
    write_json(out / "COMPLETE.json", {"status": "COMPLETED", "completed": count, "expected": len(jobs)})
    summary = analyze(out)
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-root", type=Path, default=Path(r".\data\edgeiiot_subset"))
    p.add_argument("--out-root", type=Path, default=Path(r".\experiments\e1_edge\results"))
    p.add_argument("--alphas", nargs="*", type=float, default=[0.1, 0.5, 1.0])
    p.add_argument("--seeds", type=int, default=20)
    p.add_argument("--seed-start", type=int, default=310001)
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--rounds", type=int, default=60)
    p.add_argument("--hidden", type=int, default=32,
                   help="hidden-layer width; params = hidden*(features+2)+1")
    a = p.parse_args()
    for alpha in a.alphas:
        s = run_alpha(alpha, a.data_root, a.out_root, a.seeds, a.seed_start, a.workers,
                      a.rounds, a.hidden)
        mn = s["means"]["mixed_recovery/neutral"]
        print(json.dumps({"alpha": alpha, "n_runs": s["n_runs"],
                          "neutral_applied_violating": mn["applied_violating_rounds"]["mean"],
                          "neutral_discarded_fraction": mn["discarded_steps_fraction"]["mean"],
                          "neutral_f1": mn["f1"]["mean"]},
                         ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()