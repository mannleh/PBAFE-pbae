# -*- coding: utf-8 -*-
"""E12 - training-side scale-out: K in {100, 200} clients with a ~50k-parameter
MLP (one hidden layer, 256 units, 193 inputs -> 49,665 parameters).

The audit protocol, the b = 3 budget, the ten-client round selection and the
reject-and-retain controller are unchanged. Attack targets are the two clients
carrying the largest attack-row counts in the partition; because only ten of K
clients are selected each round, attacked rounds are sparse at large K and the
attack-consequence metric is reported as a count, not as a containment claim.
"""
import argparse, json, os, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np

sys.path.insert(0, r".")
from experiments.pba_v3 import flcore, run_c_consequence, v5_response

OUT = Path(r".\experiments\e12_scale")


def build_partition(K, alpha=0.5, seed=12345):
    z = np.load(r".\data\unsw_official_subset_v3\unsw_subset.npz")
    y = z["y_train"]
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(y))
    props = rng.dirichlet([alpha] * K)
    counts = 1 + np.floor(props * (len(y) - K)).astype(int)
    counts[np.argmax(counts)] += len(y) - int(counts.sum())
    clients, start = [], 0
    for i in range(K):
        end = start + int(counts[i])
        clients.append(order[start:end].tolist())
        start = end
    assert sum(len(c) for c in clients) == len(y)
    return clients


def attack_clients(clients, y, K):
    """Keep the adversary at the same 6.7% share of the population as the
    2-of-30 design, so the coalition grows with K instead of becoming sparse."""
    n = max(2, int(round(0.067 * K)))
    shares = [(int(y[np.asarray(c, dtype=int)].sum()), i) for i, c in enumerate(clients)]
    shares.sort(reverse=True)
    return tuple(i for _, i in shares[:n]), shares[:n]


def job(args):
    K, arm, seed, hidden, rounds, part_seed = args
    selected = max(10, K // 3)
    budget = max(3, K // 10)
    z = np.load(r".\data\unsw_official_subset_v3\unsw_subset.npz")
    clients = build_partition(K, 0.5, part_seed)
    bad, shares = attack_clients(clients, z["y_train"], K)
    run_c_consequence.DROPPED_CLIENTS = bad
    v5_response.DROPPED_CLIENTS = bad
    t0 = time.perf_counter()
    r = v5_response.run_arm(arm, seed, (z, clients), rounds=rounds, selected=selected,
                            hidden=hidden, budget=budget)
    t = r["totals"]
    return {"K": K, "arm": arm, "seed": seed, "hidden": hidden,
            "selected": selected, "budget": budget,
            "params": r["dimension"],
            "attack_clients": bad, "attack_shares": shares,
            "f1": r["final"]["f1"], "precision": r["final"]["precision"],
            "recall": r["final"]["recall"], "balanced_accuracy": r["final"]["balanced_accuracy"],
            "attack_rounds": t["attack_rounds"],
            "attacked_updates_applied": t["attacked_updates_applied"],
            "prevented_bad_rounds": t["prevented_bad_rounds"],
            "honest_rounds_rejected": t["honest_rounds_rejected"],
            "rejected_rounds": t["rejected_rounds"],
            "discarded_steps": t["discarded_training_steps"],
            "audit_bytes": t["audit_total_bytes"], "audit_calls": t["audit_calls"],
            "audit_cpu_ms": t["audit_cpu_ms"], "wall_s": time.perf_counter() - t0,
            "reference_model_sha256": r["final_model_sha256"]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--clients", nargs="+", type=int, default=[100, 200])
    p.add_argument("--seeds", type=int, default=20)
    p.add_argument("--seed-start", type=int, default=310001)
    p.add_argument("--hidden", type=int, default=256)
    p.add_argument("--rounds", type=int, default=60)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--arms", nargs="+", default=["drop_noaudit", "drop_uniform_b3", "drop_neutral_b3"])
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    (a.out / "config.json").write_text(json.dumps(vars(a), indent=2, default=str), encoding="utf-8")
    jobs = [(K, arm, s, a.hidden, a.rounds, 12345) for K in a.clients for arm in a.arms
            for s in range(a.seed_start, a.seed_start + a.seeds)]
    rows, started = [], time.perf_counter()
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(job, j): j for j in jobs}
        for i, f in enumerate(as_completed(futs), 1):
            rows.append(f.result())
            if i % 10 == 0 or i == len(jobs):
                print(json.dumps({"done": i, "total": len(jobs), "elapsed_s": round(time.perf_counter() - started, 1)}), flush=True)
    rows.sort(key=lambda r: (r["K"], r["arm"], r["seed"]))
    (a.out / "rows.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    summary = {}
    for K in a.clients:
        for arm in a.arms:
            part = [r for r in rows if r["K"] == K and r["arm"] == arm]
            summary[f"K{K}/{arm}"] = {
                "f1_mean": float(np.mean([r["f1"] for r in part])),
                "f1_sd": float(np.std([r["f1"] for r in part], ddof=1)),
                "precision_mean": float(np.mean([r["precision"] for r in part])),
                "recall_mean": float(np.mean([r["recall"] for r in part])),
                "attack_rounds_mean": float(np.mean([r["attack_rounds"] for r in part])),
                "applied_mean": float(np.mean([r["attacked_updates_applied"] for r in part])),
                "discarded_steps_mean": float(np.mean([r["discarded_steps"] for r in part])),
                "honest_rejected_mean": float(np.mean([r["honest_rounds_rejected"] for r in part])),
                "audit_kb_per_round": float(np.mean([r["audit_bytes"] / max(1, r["audit_calls"]) / 1024 for r in part])),
                "audit_cpu_ms_mean": float(np.mean([r["audit_cpu_ms"] / max(1, r["audit_calls"]) for r in part])),
                "params": part[0]["params"]}
    (a.out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
