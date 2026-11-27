"""INVALID DEVELOPMENT RUNNER — preserved only to explain discarded smoke results.

Do not use for research evidence: the original separated baseline is uniform
in disguise and coverage counts include preattack rounds. Corrected, frozen
runner: experiments.pba_v3.v5_scheduler; see decision_v5_20261022/PROTOCOL.md.

This is a separate evaluation runner.  It compares uniform sampling, the
original availability-sensitive adaptive scheduler, an availability-neutral
adaptive scheduler, and a simple two-stream separated baseline.  The server
never receives attack labels; labels are used only after the audit for scoring.
"""
import argparse, json, math, statistics
from pathlib import Path
import numpy as np

from experiments.pba_v3.codec import digest
from experiments.pba_v3.repository import Keys, make_fixture, tamper
from experiments.pba_v3.verify import audit, FAIL_POLICY, FAIL_ROSTER, FAIL_RESULT_REPLAY, INCONCLUSIVE

FAILURES = (FAIL_ROSTER, FAIL_POLICY, FAIL_RESULT_REPLAY)
SCHEDULES = ("uniform", "adaptive", "neutral", "separated")

def beacon(seed, round_id):
    return digest("PBA3/v5-beacon", str(seed).encode(), str(round_id).encode())

def choose(method, r, clients, budget, scores, rng, seed):
    if method == "uniform":
        return sorted(map(int, rng.choice(clients, budget, replace=False)))
    if method in ("adaptive", "neutral"):
        floor = max(0.05, 1.0 / clients)
        p = np.asarray(scores, dtype=float) + floor
        p /= p.sum()
        return sorted(map(int, rng.choice(clients, budget, replace=False, p=p)))
    if method == "separated":
        # A deliberately simple baseline: independent integrity and
        # availability streams with a fixed 2+1 split, deduplicated.
        a = list(map(int, rng.choice(clients, min(2, budget), replace=False)))
        remain = [x for x in range(clients) if x not in a]
        b = list(map(int, rng.choice(remain, min(1, budget-len(a)), replace=False)))
        return sorted(a + b)
    raise ValueError(method)

def run_one(method, seed, rounds=60, clients=30, budget=3, dimension=256):
    rng = np.random.default_rng(seed + 91001)
    placement_rng = np.random.default_rng(seed + 91002)
    scores = np.zeros(clients, dtype=float)
    keys = Keys.generate(list(range(clients)))
    integ_targets, avail_targets = {0, 1}, {2, 3}
    active_rounds = 0
    integ_hits = integ_detected = avail_hits = avail_observed = 0
    inconclusive = 0
    total_bytes = 0
    checked = 0
    rows = []
    for r in range(rounds):
        rid = r + 1
        f = make_fixture(round_id=rid, dimension=dimension, clients=clients,
                         seed=seed * 1000 + r, keys=keys)
        slots = choose(method, r, clients, budget, scores, rng, seed)
        integrity_active = rid >= 9
        availability_active = rid >= 9
        if integrity_active:
            active_rounds += 1
            f = tamper(f, "declared_count_policy", tuple(sorted(integ_targets)))
        # Availability corruption is applied after the authenticated snapshot
        # is pinned; missing openings therefore produce INCONCLUSIVE evidence.
        if availability_active:
            for cid in avail_targets:
                f.source.pop(f"record/{cid}/opening", None)
        res = audit(f.source, f.trust, slots=slots, full=False, bound=True)
        total_bytes += int(res.total_network_bytes)
        checked += int(res.records_processed)
        if res.outcome == INCONCLUSIVE:
            inconclusive += 1
        ih = bool(set(slots) & integ_targets)
        ah = bool(set(slots) & avail_targets)
        idet = ih and any(res.record_outcomes.get(c) in FAILURES for c in integ_targets & set(slots))
        aobs = ah and any(res.record_outcomes.get(c) == INCONCLUSIVE for c in avail_targets & set(slots))
        integ_hits += int(ih); integ_detected += int(idet)
        avail_hits += int(ah); avail_observed += int(aobs)
        for c in slots:
            out = res.record_outcomes.get(c)
            if out in FAILURES:
                scores[c] += 1.0
            elif out == INCONCLUSIVE and method != "neutral":
                scores[c] += 0.5
        rows.append({"round": rid, "slots": slots, "outcome": res.outcome,
                     "integrity_hit": ih, "integrity_detected": idet,
                     "availability_hit": ah, "availability_observed": aobs,
                     "bytes": int(res.total_network_bytes)})
    return {"schedule": method, "seed": seed, "rounds": rounds, "budget": budget,
            "integrity_active_rounds": active_rounds,
            "integrity_hit_rate": integ_hits / active_rounds,
            "integrity_tdr": integ_detected / active_rounds,
            "availability_hit_rate": avail_hits / active_rounds,
            "availability_tdr": avail_observed / active_rounds,
            "inconclusive_rounds": inconclusive,
            "records_checked": checked, "bytes": total_bytes, "rows": rows}

def ci(vals):
    if len(vals) < 2: return [0.0, 0.0]
    m = statistics.mean(vals)
    return [m - 1.96 * statistics.stdev(vals) / math.sqrt(len(vals)),
            m + 1.96 * statistics.stdev(vals) / math.sqrt(len(vals))]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seeds", type=int, default=100)
    p.add_argument("--seed-start", type=int, default=200001)
    p.add_argument("--quick", action="store_true")
    p.add_argument("--dimension", type=int, default=256)
    a = p.parse_args()
    n = 8 if a.quick else a.seeds
    seeds = [a.seed_start + i for i in range(n)]
    rows = [run_one(s, seed, dimension=a.dimension) for s in SCHEDULES for seed in seeds]
    summary = {}
    for method in SCHEDULES:
        part = [x for x in rows if x["schedule"] == method]
        summary[method] = {k: float(np.mean([x[k] for x in part]))
                           for k in ("integrity_tdr", "availability_tdr", "inconclusive_rounds", "bytes", "records_checked")}
        for k in ("integrity_tdr", "availability_tdr", "inconclusive_rounds", "bytes"):
            summary[method][k + "_ci"] = ci([x[k] for x in part])
    paired = {}
    base = {x["seed"]: x for x in rows if x["schedule"] == "uniform"}
    for method in SCHEDULES[1:]:
        cur = {x["seed"]: x for x in rows if x["schedule"] == method}
        paired[method] = {}
        for k in ("integrity_tdr", "availability_tdr", "inconclusive_rounds", "bytes"):
            diffs = [cur[s][k] - base[s][k] for s in seeds]
            paired[method][k] = {"mean_diff": float(np.mean(diffs)), "ci95": ci(diffs)}
    out = {"protocol": {"schedules": SCHEDULES, "seeds": seeds, "dimension": a.dimension,
                         "integrity_targets": [0, 1], "availability_targets": [2, 3],
                         "attack_onset_round": 9, "budget": 3},
           "summary": summary, "paired_vs_uniform": paired, "rows": rows}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=2), encoding="utf8")
    print(json.dumps({"rows": len(rows), "out": str(a.out)}, indent=2))

if __name__ == "__main__":
    raise RuntimeError("Invalid development runner; use experiments.pba_v3.v5_scheduler")
