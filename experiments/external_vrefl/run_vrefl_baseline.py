# -*- coding: utf-8 -*-
"""Run the VREFL verification core on the released PBA/3 bridge fixture."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

for _n in ("OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "OMP_NUM_THREADS"):
    os.environ[_n] = "1"
sys.path.insert(0, r".")
import numpy as np
from experiments.pba_v3 import flcore, v5_response, v6_bridge
from experiments.pba_v3.run_c_consequence import DROPPED_CLIENTS, load
from experiments.pba_v3.v5_common import bootstrap, file_hash, write_json
from experiments.external_vrefl.vrefl_core import parameters, server_annotate, verify_fixture

_DATA_CACHE = {}


def _job(job):
    scenario, seed, data_dir, rounds = job
    if data_dir not in _DATA_CACHE:
        _DATA_CACHE[data_dir] = load(data_dir)
    data = _DATA_CACHE[data_dir]
    z, clients = data
    Xtr, ytr = z["X_train"], z["y_train"]
    Xte, yte = z["X_test"], z["y_test"]
    client_count = len(clients)
    rng = np.random.default_rng(seed)
    dimension = Xtr.shape[1]
    hidden = 32
    w = np.concatenate([rng.normal(0, .05, dimension * hidden), np.zeros(hidden),
                        rng.normal(0, .05, hidden), np.zeros(1)])
    initial_hash = hashlib.sha256(w.tobytes()).hexdigest()
    bases = parameters(len(w))
    counts_all = [len(block) for block in clients]
    class_weights = {label: len(ytr) / (2 * max(1, int((ytr == label).sum())))
                     for label in (0, 1)}
    keys = v6_bridge.Keys.generate(list(range(client_count)))
    withholding_ids = v6_bridge.withholding_slots(seed, client_count)
    totals = dict(
        attack_rounds=0, attacked_updates_applied=0, attacked_records_applied=0,
        prevented_bad_rounds=0, rejected_rounds=0, honest_rounds_rejected=0,
        audit_calls=0, full_audit_calls=0, actual_replays=0, aggregate_verified=0,
        inconclusive_calls=0, audit_requests=0, audit_missing_requests=0,
        audit_request_bytes=0, audit_response_payload_bytes=0,
        audit_response_framing_bytes=0, audit_total_bytes=0,
        audit_cpu_ms=0.0, audit_wall_ms=0.0, server_lhh_ms=0.0,
        training_wall_ms=0.0, evidence_build_wall_ms=0.0,
        local_training_steps=0, local_rows_processed=0,
        discarded_training_steps=0, discarded_rows_processed=0,
        records_processed=0, updates_processed=0,
    )
    round_rows, schedule = [], []
    for r in range(rounds):
        before_model_hash = hashlib.sha256(w.tobytes()).hexdigest()
        chosen = sorted(map(int, rng.choice(client_count, 10, replace=False)))
        schedule.append(chosen)
        start = time.perf_counter_ns()
        vectors, counts, rows_processed = [], [], 0
        for cid in chosen:
            ids = np.asarray(clients[cid], dtype=int)
            local_rng = np.random.default_rng(np.random.SeedSequence([seed, r, cid, 71]))
            vectors.append(flcore.local_update(w, Xtr[ids], ytr[ids], hidden, local_rng,
                                              lr=.03, class_weights=class_weights))
            counts.append(counts_all[cid])
            rows_processed += min(128, len(ids))
        totals["training_wall_ms"] += (time.perf_counter_ns() - start) / 1e6
        totals["local_training_steps"] += len(chosen)
        totals["local_rows_processed"] += rows_processed
        active = scenario == "mixed_recovery" and 20 <= r < 60
        aggregate = v5_response.published_aggregate(vectors, counts, chosen, active)
        start = time.perf_counter_ns()
        f = v5_response.build_training_fixture(w, vectors, counts, chosen, client_count,
                                               seed, r + 1, keys, active, aggregate)
        totals["evidence_build_wall_ms"] += (time.perf_counter_ns() - start) / 1e6
        start = time.perf_counter_ns()
        server_annotate(f, bases)
        totals["server_lhh_ms"] += (time.perf_counter_ns() - start) / 1e6
        unavailable = withholding_ids if 20 <= r < 40 else []
        withheld = v6_bridge.withhold(f, unavailable) if unavailable else []
        outcome, stats = verify_fixture(f, bases)
        totals["audit_calls"] += 1
        totals["full_audit_calls"] += 1
        totals["actual_replays"] += int(outcome == "PASS")
        totals["aggregate_verified"] += int(outcome == "PASS")
        totals["inconclusive_calls"] += int(outcome == "INCONCLUSIVE_EVIDENCE")
        totals["audit_total_bytes"] += stats["bytes_read"]
        totals["audit_cpu_ms"] += stats["cpu_ms"]
        totals["audit_wall_ms"] += stats["cpu_ms"]
        totals["records_processed"] += stats["records_read"]
        totals["updates_processed"] += stats["records_read"]
        rejected = v5_response.reject_round(outcome)
        w = v5_response.next_model(w, aggregate, outcome)
        targets = sorted(set(chosen).intersection(DROPPED_CLIENTS)) if active else []
        attacked = bool(targets)
        totals["attack_rounds"] += int(attacked)
        totals["attacked_updates_applied"] += int(attacked and not rejected)
        totals["attacked_records_applied"] += len(targets) if not rejected else 0
        totals["prevented_bad_rounds"] += int(attacked and rejected)
        totals["rejected_rounds"] += int(rejected)
        totals["honest_rounds_rejected"] += int(not attacked and rejected)
        totals["discarded_training_steps"] += len(chosen) if rejected else 0
        totals["discarded_rows_processed"] += rows_processed if rejected else 0
        round_rows.append({
            "round": r + 1, "chosen": chosen, "attack_targets": targets,
            "previous_model_sha256": before_model_hash,
            "applied_model_sha256": hashlib.sha256(w.tobytes()).hexdigest(),
            "audit_slots": list(range(client_count)), "outcome": outcome,
            "rejected": rejected, "audit_bytes": stats["bytes_read"],
            "audit_cpu_ms": stats["cpu_ms"], "records_read": stats["records_read"],
            "audit_requests": stats["records_read"],
            "missing_requests": int(outcome == "INCONCLUSIVE_EVIDENCE"),
            "withheld_objects": withheld, "reason": stats["reason"],
            "trained_rows": rows_processed, "local_steps": len(chosen),
        })
    bridge = v6_bridge.trace_metrics(round_rows)
    final = flcore.metrics(yte, (flcore.predict(w, Xte, hidden) >= .5).astype(int))
    return {
        "scenario": scenario, "method": "vrefl_full", "seed": seed, "rounds": rounds,
        "audit_budget": client_count, "withholding_ids": withholding_ids,
        "bridge": bridge, "final": final, "totals": totals, "round_rows": round_rows,
        "initial_model_sha256": initial_hash,
        "final_model_sha256": hashlib.sha256(w.tobytes()).hexdigest(),
        "selection_schedule_sha256": hashlib.sha256(json.dumps(schedule).encode()).hexdigest(),
        "dimension": len(w), "clients": client_count,
        "train_rows": len(ytr), "test_rows": len(yte),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", type=Path, default=Path(r".\data\unsw_official_subset_v3"))
    p.add_argument("--out", type=Path, default=Path(r".\experiments\external_vrefl\results_bridge"))
    p.add_argument("--seeds", type=int, default=20)
    p.add_argument("--seed-start", type=int, default=310001)
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--rounds", type=int, default=60)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    cfg = {
        "baseline": "VREFL verification core (LHH + Merkle), not full secure aggregation/CRT",
        "citation": "Ye et al., JNCA 207 (2022) 103486, doi:10.1016/j.jnca.2022.103486",
        "data_dir": str(a.data_dir.resolve()), "out": str(a.out.resolve()),
        "seed_start": a.seed_start, "seeds": a.seeds, "rounds": a.rounds,
        "scenarios": ["mixed_recovery", "withholding_recovery"], "methods": ["vrefl_full"],
        "source_sha256": {str(path): file_hash(path) for path in (
            Path(__file__).resolve(),
            Path(r".\experiments\external_vrefl\vrefl_core.py"),
            Path(v6_bridge.__file__).resolve(), Path(v5_response.__file__).resolve())},
        "data_sha256": {name: file_hash(a.data_dir / name) for name in
                        ("unsw_subset.npz", "client_indices.json")},
        "numpy_version": np.__version__, "status": "RUNNING",
    }
    write_json(a.out / "config.json", cfg)
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
                                      "applied": row["bridge"]["applied_violating_rounds"],
                                      "audit_MB": row["totals"]["audit_total_bytes"] / 1e6}), flush=True)
    except BaseException as exc:
        write_json(a.out / "FAILED.json", {"error": repr(exc), "completed": count,
                                           "expected": len(jobs)})
        raise
    write_json(a.out / "COMPLETE.json", {"status": "COMPLETED", "completed": count,
                                         "expected": len(jobs)})


if __name__ == "__main__":
    main()
