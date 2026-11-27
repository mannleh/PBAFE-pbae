"""P1.6 anchor check: reproduce withholding/adaptive vs withholding/uniform from the
current pba_v2 code, independent of the frozen release_v3 CSV.

Writes experiments/pba_v3/results/anchor_check/ with per-seed rows and a summary.
"""
import argparse
import json
import statistics
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from experiments.pba_v2.run_budget_v3 import one


def job(args):
    method, seed = args
    r = one(method, "withholding", seed, rounds=60, clients=30, budget=3, dimension=256)
    r.pop("audit_outcomes", None)
    return r


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seeds", type=int, default=100)
    p.add_argument("--workers", type=int, default=10)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)

    jobs = [(m, 100000 + s) for m in ("adaptive", "uniform") for s in range(a.seeds)]
    rows = []
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        for i, r in enumerate(ex.map(job, jobs, chunksize=2), 1):
            rows.append(r)
            if i % 25 == 0:
                print(json.dumps({"done": i, "total": len(jobs)}), flush=True)

    summary = {}
    for m in ("adaptive", "uniform"):
        part = [r for r in rows if r["method"] == m]
        inc = [r["inconclusive"] for r in part]
        tdr = [r["record_level_tdr"] for r in part]
        cov = [r["attack_coverage"] for r in part]
        byt = [r["bytes_read"] for r in part]
        inc_rounds = [r["inconclusive_attack_rounds"] for r in part]
        summary[m] = {
            "n": len(part),
            "inconclusive_mean": statistics.mean(inc),
            "inconclusive_sd": statistics.stdev(inc),
            "inconclusive_ci95": 1.96 * statistics.stdev(inc) / len(inc) ** 0.5,
            "inconclusive_attack_rounds_mean": statistics.mean(inc_rounds),
            "coverage_mean": statistics.mean(cov),
            "tdr_mean": statistics.mean(tdr),
            "bytes_mean": statistics.mean(byt),
        }
    diff = [a2["inconclusive"] - u["inconclusive"]
            for a2, u in zip(sorted([r for r in rows if r["method"] == "adaptive"], key=lambda x: x["seed"]),
                             sorted([r for r in rows if r["method"] == "uniform"], key=lambda x: x["seed"]))]
    summary["paired_adaptive_minus_uniform_inconclusive"] = {
        "mean": statistics.mean(diff),
        "ci95_low": statistics.mean(diff) - 1.96 * statistics.stdev(diff) / len(diff) ** 0.5,
        "ci95_high": statistics.mean(diff) + 1.96 * statistics.stdev(diff) / len(diff) ** 0.5,
    }
    summary["reference_release_v3"] = {"adaptive": 47.260, "uniform": 10.460}

    (a.out / "anchor_rows.json").write_text(json.dumps(rows, indent=2), encoding="utf8")
    (a.out / "anchor_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
