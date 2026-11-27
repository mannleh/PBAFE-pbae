# -*- coding: utf-8 -*-
"""E2c - audit-side dimension scaling (anchors for the E13 cost model).

Measures sampled audit cost at model dimensions d in {6,241; 49,921; 99,841}
and client populations K in {30, 100}, budgets b = 3 and b = K/10. No training.
"""
import json, statistics, sys, time
from pathlib import Path

sys.path.insert(0, r".")
import psutil
from experiments.pba_v3.repository import Keys, make_fixture
from experiments.pba_v3.verify import audit

OUT = Path(r".\experiments\e2c_dimension")
DIMS = (6241, 49921, 99841)
KS = (30, 100)
REPEATS = 3


def measure(K, d, b, rounds=3):
    keys = Keys.generate(list(range(K)))
    rows = []
    for rid in range(1, rounds + 1):
        f = make_fixture(round_id=rid, dimension=d, clients=K, seed=700000 + rid, keys=keys)
        slots = list(range(b))
        t0 = time.perf_counter(); c0 = time.process_time()
        r = audit(f.source, f.trust, slots=slots)
        rows.append({"wall_ms": (time.perf_counter() - t0) * 1e3,
                     "cpu_ms": (time.process_time() - c0) * 1e3,
                     "bytes": r.total_network_bytes, "requests": len(r.requests),
                     "rss_mb": psutil.Process().memory_info().rss / 1e6})
    return {"K": K, "dimension": d, "budget": b, "rounds": rounds,
            "wall_ms": statistics.mean(x["wall_ms"] for x in rows),
            "cpu_ms": statistics.mean(x["cpu_ms"] for x in rows),
            "bytes": statistics.mean(x["bytes"] for x in rows),
            "requests": statistics.mean(x["requests"] for x in rows),
            "rss_mb": max(x["rss_mb"] for x in rows)}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    res = []
    for K in KS:
        for d in DIMS:
            for b in (3, max(3, K // 10)):
                r = measure(K, d, b)
                res.append(r)
                print(json.dumps(r, ensure_ascii=False))
    (OUT / "E2c_results.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
