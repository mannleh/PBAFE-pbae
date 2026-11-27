"""Run B: segment-sum tier detection bound vs bytes.

Grid: segments S x density rho (fraction of segments whose published sum is
corrupted) x segment budget b. For each cell we record whether the tamper was
detected and the bytes read, then compare the empirical miss rate against the
hypergeometric bound  P_miss = C(S-m,b)/C(S,b).

Corruption model: the server publishes a wrong segment sum for m segments and
leaves every per-record contribution honest. This is the strongest position
for the attacker: it violates nothing except the sum itself.
"""
import argparse
import json
import math
import random
import statistics
from pathlib import Path

from experiments.pba_v3.codec import derive_challenge_seed
from experiments.pba_v3.segfixture import add_segments, build_segment_fixture
from experiments.pba_v3.verify import FAIL_RESULT_REPLAY, audit_segment


def miss_bound(S, m, b):
    if m <= 0:
        return 1.0
    if b > S - m:
        return 0.0
    return math.comb(S - m, b) / math.comb(S, b)


def one(S, m, b, seed, dimension=64, clients=10):
    f = build_segment_fixture(round_id=1, dimension=dimension, clients=clients, segments=S, seed=seed)
    rng = random.Random(seed)
    corrupt = sorted(rng.sample(range(S), m))
    # One call: re-deriving after each single-segment tamper would silently
    # restore the previously corrupted segments.
    g = add_segments(f, S, tamper_segments=corrupt)
    from experiments.pba_v3.codec import digest
    seed_hex = derive_challenge_seed(g.trust.bulletin_pin, 1, digest("PBA3/beacon", str(seed).encode()))
    r = audit_segment(g.source, g.trust, seed_hex, b)
    detected = r.outcome == FAIL_RESULT_REPLAY
    return {"S": S, "m": m, "rho": m / S, "b": b, "seed": seed,
            "detected": detected, "outcome": r.outcome,
            "bytes": r.total_network_bytes, "wall_ms": r.wall_ms}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seeds", type=int, default=20)
    p.add_argument("--segments", nargs="*", type=int, default=[8, 16, 32])
    p.add_argument("--budgets", nargs="*", type=int, default=[1, 2, 4])
    p.add_argument("--densities", nargs="*", type=float, default=[0.0625, 0.125, 0.25, 1.0])
    a = p.parse_args()

    rows = []
    for S in a.segments:
        for rho in a.densities:
            m = max(1, int(round(S * rho)))
            for b in a.budgets:
                if b > S:
                    continue
                for i in range(a.seeds):
                    rows.append(one(S, m, b, 1000 + i))

    summary = []
    seen = set()
    for S in a.segments:
        for rho in a.densities:
            m = max(1, int(round(S * rho)))
            for b in a.budgets:
                if b > S or (S, m, b) in seen:
                    continue
                seen.add((S, m, b))
                part = [r for r in rows if r["S"] == S and r["m"] == m and r["b"] == b]
                if not part:
                    continue
                hit = sum(r["detected"] for r in part) / len(part)
                summary.append({
                    "S": S, "m": m, "rho": round(m / S, 4), "b": b, "n": len(part),
                    "detected": round(hit, 4),
                    "miss_empirical": round(1 - hit, 4),
                    "miss_bound": round(miss_bound(S, m, b), 4),
                    "bytes": round(statistics.mean(r["bytes"] for r in part), 1),
                    "wall_ms": round(statistics.mean(r["wall_ms"] for r in part), 2),
                })
    out = {"note": "corruption = published segment sums; contributions honest",
           "summary": summary, "rows": rows}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=2), encoding="utf8")
    print(json.dumps({"rows": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
