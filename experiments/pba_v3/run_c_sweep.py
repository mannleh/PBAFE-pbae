"""C sweep: how much does the audit buy, as a function of its budget?

The single-point comparison at b=3 caught too few rounds to separate the
regimes, which is itself the finding: an audit's value is bounded by the
probability that it samples the affected slot. This script measures that
relationship directly by holding the manipulation fixed and varying only the
record budget.

Outputs one row per (budget, seed) plus a summary, and writes the baseline
(no attack) and no-audit arms once so the three can be compared.
"""
import argparse
import json
import statistics
from pathlib import Path

from experiments.pba_v3.run_c_consequence import load, run_regime


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", type=Path, default=Path("data/unsw_official_subset_v3"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seeds", nargs="*", type=int, default=[101, 102, 103, 104, 105])
    p.add_argument("--budgets", nargs="*", type=int, default=[3, 10, 30])
    p.add_argument("--attack", default="drop_client")
    p.add_argument("--rounds", type=int, default=60)
    p.add_argument("--hidden", type=int, default=32)
    a = p.parse_args()

    data = load(a.data_dir)
    rows = []

    for seed in a.seeds:
        r = run_regime("no_audit", "none", seed, data, data[1],
                       rounds=a.rounds, hidden=a.hidden)
        rows.append({"arm": "clean", "budget": 0, "seed": seed,
                     "f1": r["final"]["f1"], "detection_rate": 0.0})
        print(json.dumps({"arm": "clean", "seed": seed, "f1": round(r["final"]["f1"], 4)}),
              flush=True)

    for seed in a.seeds:
        r = run_regime("no_audit", a.attack, seed, data, data[1],
                       rounds=a.rounds, hidden=a.hidden)
        rows.append({"arm": "no_audit", "budget": 0, "seed": seed,
                     "f1": r["final"]["f1"], "detection_rate": 0.0})
        print(json.dumps({"arm": "no_audit", "seed": seed, "f1": round(r["final"]["f1"], 4)}),
              flush=True)

    for b in a.budgets:
        for seed in a.seeds:
            r = run_regime("caught", a.attack, seed, data, data[1],
                           rounds=a.rounds, hidden=a.hidden, audit_budget=b)
            rows.append({"arm": "caught", "budget": b, "seed": seed,
                         "f1": r["final"]["f1"],
                         "detection_rate": r["detection_rate"]})
            print(json.dumps({"arm": "caught", "budget": b, "seed": seed,
                              "f1": round(r["final"]["f1"], 4),
                              "det": round(r["detection_rate"], 3)}), flush=True)

    def cell(sel):
        part = [r for r in rows if sel(r)]
        f1 = [r["f1"] for r in part]
        det = [r["detection_rate"] for r in part]
        return {"n": len(part),
                "f1": statistics.mean(f1),
                "f1_sd": statistics.stdev(f1) if len(f1) > 1 else 0.0,
                "detection_rate": statistics.mean(det)}

    summary = {
        "clean": cell(lambda r: r["arm"] == "clean"),
        "no_audit": cell(lambda r: r["arm"] == "no_audit"),
        "caught": {str(b): cell(lambda r, bb=b: r["arm"] == "caught" and r["budget"] == bb)
                   for b in a.budgets},
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
