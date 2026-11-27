# -*- coding: utf-8 -*-
"""E2b — audit-cost scaling with client population K in {30, 100, 200}.

No training is run here: this measures the verification side only (bytes,
requests, CPU, full-round replay time) for b = 3 and b = K, at dimension 256.
Reported separately from detection, which is not evaluated at K > 30.
"""
import json, statistics, sys, time
from pathlib import Path
sys.path.insert(0, r".")
from experiments.pba_v3.repository import Keys, make_fixture, tamper
from experiments.pba_v3.verify import audit

OUT = Path(r".\experiments\e2_scaling")
OUT.mkdir(parents=True, exist_ok=True)
DIM = 256
REPEATS = 5


def run(K, budget, full):
    keys = Keys.generate(list(range(K)))
    f = make_fixture(round_id=500, dimension=DIM, clients=K, seed=900 + K, keys=keys)
    bad = (0, 1)
    f = tamper(f, "declared_count_policy", bad)
    rows = []
    for _ in range(REPEATS):
        t0 = time.perf_counter(); c0 = time.process_time()
        r = audit(f.source, f.trust, slots=list(range(budget)) if not full else (), full=full)
        rows.append({"wall_ms": (time.perf_counter() - t0) * 1e3,
                     "cpu_ms": (time.process_time() - c0) * 1e3,
                     "bytes": r.total_network_bytes, "requests": len(r.requests),
                     "outcome": r.outcome})
    return {"K": K, "budget": K if full else budget, "full": full,
            "bytes_mean": statistics.mean(x["bytes"] for x in rows),
            "requests_mean": statistics.mean(x["requests"] for x in rows),
            "cpu_ms_mean": statistics.mean(x["cpu_ms"] for x in rows),
            "wall_ms_mean": statistics.mean(x["wall_ms"] for x in rows),
            "outcome": rows[0]["outcome"]}


def main():
    res = []
    for K in (30, 100, 200):
        res.append(run(K, 3, False))
        res.append(run(K, K, True))
    (OUT / "E2_results.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{'K':>5}{'b':>6}{'bytes':>12}{'requests':>10}{'cpu_ms':>9}{'wall_ms':>9}  outcome")
    for r in res:
        print(f"{r['K']:>5}{r['budget']:>6}{r['bytes_mean']:>12.0f}{r['requests_mean']:>10.1f}"
              f"{r['cpu_ms_mean']:>9.1f}{r['wall_ms_mean']:>9.1f}  {r['outcome']}")


if __name__ == "__main__":
    main()