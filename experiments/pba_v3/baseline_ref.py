"""P0.4 regression baseline for the v3 package.

Runs a compact grid through the *copied* v3 modules (not v2) so that any
future edit to codec/verify/repository is checked against a frozen reference.
Writes baseline_ref.json with per-row and per-cell summaries.
"""
import argparse
import json
import statistics
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

from experiments.pba_v3.repository import make_fixture, tamper
from experiments.pba_v3.verify import audit, INCONCLUSIVE

FAILURES = ("FAIL_ROSTER", "FAIL_POLICY", "FAIL_RESULT_REPLAY")

ATTACKS = ("persistent", "random", "withholding")
METHODS = ("uniform", "round_robin", "adaptive", "fixed_low", "fixed_high",
           "periodic_full", "policy_blind")


def attack_trace(attack, seed, rounds=60, clients=30):
    """Verbatim copy of pba_v2.run_budget_v3.attack_trace (v3 owns its traces)."""
    rng = np.random.default_rng(seed)
    rows = []
    for r in range(rounds):
        if attack == "random":
            ids = set(map(int, rng.choice(clients, 2, replace=False))) if rng.random() < .35 else set()
            rows.append({"ids": ids, "kind": "record", "withhold": False})
        elif attack == "persistent":
            rows.append({"ids": {0, 1} if r >= 8 else set(), "kind": "record", "withhold": False})
        elif attack == "withholding":
            rows.append({"ids": {0, 1} if r >= 8 else set(), "kind": "record", "withhold": True})
        else:
            raise ValueError(attack)
    return rows


def make_attack_round(event, round_id, seed, dimension=256, clients=30):
    fixture = make_fixture(round_id=round_id, dimension=dimension, clients=clients, seed=seed)
    ids = tuple(sorted(event["ids"]))
    if event["withhold"] and ids:
        for cid in ids:
            fixture.source.pop(f"record/{cid}/opening", None)
        return fixture
    if ids:
        return tamper(fixture, "declared_count_policy", ids)
    return fixture


def schedule(method, round_id, clients, budget, rng, scores):
    if method == "no_audit":
        return "none", []
    if method == "fixed_low":
        return "spot", sorted(map(int, rng.choice(clients, 1, replace=False)))
    if method in ("uniform", "policy_blind"):
        return "spot", sorted(map(int, rng.choice(clients, budget, replace=False)))
    if method == "round_robin":
        return "spot", [(round_id * budget + j) % clients for j in range(budget)]
    if method == "adaptive":
        floor = max(0.05, 1.0 / clients)
        weights = np.asarray(scores, dtype=float) + floor
        weights /= weights.sum()
        return "spot", sorted(map(int, rng.choice(clients, budget, replace=False, p=weights)))
    if method == "periodic_full":
        return ("full", list(range(clients))) if (round_id + 1) % 10 == 0 else ("none", [])
    if method == "fixed_high":
        return "full", list(range(clients))
    raise ValueError(method)


def update_risk_scores(scores, result, slots):
    for cid in slots:
        outcome = result.record_outcomes.get(cid)
        if outcome in ("FAIL_ROSTER", "FAIL_POLICY", "FAIL_RESULT_REPLAY"):
            scores[cid] += 1.0
        elif outcome == INCONCLUSIVE:
            scores[cid] += 0.5


def one(method, attack, seed, rounds=60, clients=30, budget=3, dimension=256):
    events = attack_trace(attack, seed, rounds, clients)
    audit_rng = np.random.default_rng(seed + 7919)
    scores = np.zeros(clients, dtype=float)
    attack_rounds = sum(1 for e in events if e["ids"])
    covered = set()
    detected = set()
    inconclusive = 0
    inconclusive_attack_rounds = set()
    total_bytes = 0
    checks = 0
    for r, event in enumerate(events):
        scope, slots = schedule(method, r, clients, budget, audit_rng, scores)
        if scope == "none":
            continue
        fixture = make_attack_round(event, r + 1, seed * 1000 + r, dimension, clients)
        bound = method != "policy_blind"
        result = audit(fixture.source, fixture.trust, slots=slots, full=(scope == "full"), bound=bound)
        checks += len(slots) if scope == "spot" else clients
        total_bytes += result.total_network_bytes
        if result.outcome == INCONCLUSIVE:
            inconclusive += 1
            if event["ids"] and set(slots) & set(event["ids"]):
                inconclusive_attack_rounds.add(r)
        truth = set(event["ids"])
        if truth and scope == "spot" and truth & set(slots):
            covered.add(r)
            if any(result.record_outcomes.get(c) in
                   ("FAIL_ROSTER", "FAIL_POLICY", "FAIL_RESULT_REPLAY")
                   for c in truth & set(slots)):
                detected.add(r)
        elif truth and scope == "full":
            # A full audit covers every attack round it is scheduled on, but an
            # INCONCLUSIVE outcome is an availability result, never a detection.
            covered.add(r)
            if result.outcome in FAILURES:
                detected.add(r)
        if method == "adaptive" and scope == "spot":
            update_risk_scores(scores, result, slots)
    return {
        "method": method, "attack": attack, "seed": seed,
        "record_budget": budget, "dimension": dimension,
        "attack_rounds": attack_rounds,
        "coverage": len(covered) / attack_rounds if attack_rounds else 0.0,
        "tdr": len(detected) / attack_rounds if attack_rounds else 0.0,
        "inconclusive": inconclusive,
        "inconclusive_attack_rounds": len(inconclusive_attack_rounds),
        "checks": checks,
        "bytes_read": total_bytes,
    }


def _job(args):
    return one(*args)


def mean_ci(vals):
    a = np.asarray(vals, dtype=float)
    return float(a.mean()), float(1.96 * a.std(ddof=1) / len(a) ** 0.5) if len(a) > 1 else 0.0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, default=Path("experiments/pba_v3/results/baseline_ref.json"))
    p.add_argument("--seeds", type=int, default=10)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--dimension", type=int, default=256)
    a = p.parse_args()

    jobs = [(m, atk, 100000 + s, 60, 30, 3, a.dimension)
            for atk in ATTACKS for m in METHODS for s in range(a.seeds)]
    rows = []
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        for i, r in enumerate(ex.map(_job, jobs, chunksize=2), 1):
            rows.append(r)
            if i % 40 == 0:
                print(json.dumps({"done": i, "total": len(jobs)}), flush=True)

    summary = []
    for atk in ATTACKS:
        for m in METHODS:
            part = [r for r in rows if r["attack"] == atk and r["method"] == m]
            cell = {"attack": atk, "method": m, "n": len(part)}
            for key in ("tdr", "coverage", "inconclusive", "inconclusive_attack_rounds",
                        "bytes_read", "checks"):
                mu, ci = mean_ci([r[key] for r in part])
                cell[key + "_mean"], cell[key + "_95ci"] = mu, ci
            summary.append(cell)

    out = {
        "config_version": "PBA3/config-v1",
        "status": "regression-baseline",
        "seeds": a.seeds, "dimension": a.dimension,
        "note": "Compact regression grid. Paper tables must use the full "
                "100-seed grid at FINAL_DIMENSION (P3.3).",
        "summary": summary, "rows": rows,
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=2), encoding="utf8")
    print(json.dumps({"rows": len(rows), "out": str(a.out)}, indent=2))


if __name__ == "__main__":
    main()
