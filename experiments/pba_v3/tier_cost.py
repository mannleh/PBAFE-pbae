"""P2.6: per-tier cost at the real model dimension.

record  : b sampled records, local evidence only
segment : b sampled segments rebuilt from committed per-record contributions
full    : every accepted update read and replayed

All three run against the same fixture so bytes and wall time are comparable
without a cross-protocol extrapolation.
"""
import argparse
import json
import statistics
from pathlib import Path

from experiments.pba_v3.codec import derive_challenge_seed, digest
from experiments.pba_v3.segfixture import add_segments, build_segment_fixture
from experiments.pba_v3.verify import audit, audit_segment


def one(dimension, clients, segments, b, seed):
    f = build_segment_fixture(round_id=1, dimension=dimension, clients=clients,
                              segments=segments, seed=seed)
    f = add_segments(f, segments)
    beacon = digest("PBA3/beacon", str(seed).encode())
    seed_hex = derive_challenge_seed(f.trust.bulletin_pin, 1, beacon)
    from experiments.pba_v3.codec import sealed_sample
    slots = sealed_sample(seed_hex, [1.0] * clients, b)
    rec = audit(f.source, f.trust, slots=slots)
    seg = audit_segment(f.source, f.trust, seed_hex, b, segments=segments)
    full = audit(f.source, f.trust, full=True)
    return {"dimension": dimension, "clients": clients, "segments": segments, "b": b,
            "seed": seed,
            "record": {"bytes": rec.total_network_bytes, "wall_ms": rec.wall_ms,
                       "records": rec.records_processed},
            "segment": {"bytes": seg.total_network_bytes, "wall_ms": seg.wall_ms,
                        "outcome": seg.outcome, "segments": getattr(seg, "segments_checked", 0)},
            "full": {"bytes": full.total_network_bytes, "wall_ms": full.wall_ms,
                     "updates": full.updates_processed}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--dimensions", nargs="*", type=int, default=[256, 6241])
    p.add_argument("--clients", type=int, default=30)
    p.add_argument("--segments", type=int, default=16)
    p.add_argument("--budget", type=int, default=3)
    p.add_argument("--seeds", type=int, default=3)
    a = p.parse_args()

    rows = [one(d, a.clients, a.segments, a.budget, 1000 + i)
            for d in a.dimensions for i in range(a.seeds)]
    summary = {}
    for d in a.dimensions:
        part = [r for r in rows if r["dimension"] == d]
        for tier in ("record", "segment", "full"):
            summary[f"{d}/{tier}"] = {
                "bytes": round(statistics.mean(r[tier]["bytes"] for r in part), 1),
                "wall_ms": round(statistics.mean(r[tier]["wall_ms"] for r in part), 2),
                "n": len(part),
            }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
