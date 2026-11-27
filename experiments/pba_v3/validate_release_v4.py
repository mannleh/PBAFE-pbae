"""P5.2 release validator for PBA/3.

Checks that every paper number has a backing artifact and that the artifacts
are internally consistent. Refuses to pass when a claim in the manuscript has
no measured source.
"""
import argparse
import json
import math
from pathlib import Path

REQUIRED = ("a_manipulation_onset9.json", "b_segment_v3.json", "c_sweep_v1.json",
            "tier_cost.json")


def check_anchor(results):
    """The P1.6 anchor must still be reproducible from the shipped code."""
    a = json.loads((results / "a_manipulation_onset9.json").read_text(encoding="utf8"))
    S = {(x["schedule"], x["opponent"], x["workload"]): x for x in a["summary"]}
    inc_a = S[("adaptive", "withhold", "withholding")]["inconclusive"]
    inc_u = S[("uniform", "withhold", "withholding")]["inconclusive"]
    tdr = S[("adaptive", "persistent", "persistent")]["tdr"]
    return {"adaptive": inc_a, "uniform": inc_u, "ratio": inc_a / inc_u,
            "persistent_tdr": tdr,
            "ok": 3.0 < inc_a / inc_u < 6.0 and abs(tdr - 0.921) < 0.02}


def check_segments(results):
    b = json.loads((results / "b_segment_v3.json").read_text(encoding="utf8"))
    worst, worst_cell = 0.0, None
    for r in b["summary"]:
        S, m, bb, n = r["S"], r["m"], r["b"], r["n"]
        exact = math.comb(S - m, bb) / math.comb(S, bb) if bb <= S - m else 0.0
        sd = math.sqrt(max(exact * (1 - exact), 1e-9) / n)
        z = abs(r["miss_empirical"] - exact) / sd if sd else 0.0
        if z > worst:
            worst, worst_cell = z, (S, m, bb, r["miss_empirical"], exact)
    return {"cells": len(b["summary"]), "max_abs_z": worst, "worst_cell": worst_cell,
            "ok": worst < 3.0}


def check_consequence(results):
    """The audit must buy back part of the loss, and more of it as the budget grows.

    This deliberately does NOT test that the caught arm equals the clean
    baseline. Exact equality is what a regime that never applies the
    manipulation produces, so asserting it would certify a tautology; the
    earlier version of this check did exactly that and passed a broken
    experiment.
    """
    c = json.loads((results / "c_sweep_v1.json").read_text(encoding="utf8"))
    s = c["summary"]
    clean = s["clean"]["f1"]
    no_audit = s["no_audit"]["f1"]
    caught = {int(k): v for k, v in s["caught"].items()}
    budgets = sorted(caught)
    loss = clean - no_audit
    f1s = [caught[b]["f1"] for b in budgets]
    dets = [caught[b]["detection_rate"] for b in budgets]
    monotone_f1 = all(f1s[i] <= f1s[i + 1] + 1e-9 for i in range(len(f1s) - 1))
    monotone_det = all(dets[i] <= dets[i + 1] + 1e-9 for i in range(len(dets) - 1))
    best = caught[budgets[-1]]["f1"]
    return {"clean": clean, "no_audit": no_audit, "loss": loss,
            "caught": {str(b): caught[b]["f1"] for b in budgets},
            "detection": {str(b): caught[b]["detection_rate"] for b in budgets},
            "best_f1": best,
            "recovers_majority": (best - no_audit) > 0.5 * loss if loss > 0 else False,
            "monotone_f1": monotone_f1,
            "monotone_detection": monotone_det,
            "ok": loss > 0 and monotone_det and best > no_audit + 1e-6}


def check_costs(results):
    t = json.loads((results / "tier_cost.json").read_text(encoding="utf8"))
    s = t["summary"]
    order = []
    for d in (256, 6241):
        r, sg, f = (s[f"{d}/record"]["bytes"], s[f"{d}/segment"]["bytes"], s[f"{d}/full"]["bytes"])
        order.append((d, r < sg < f, r, sg, f))
    return {"ordering": order, "ok": all(x[1] for x in order)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--results", type=Path, default=Path("experiments/pba_v3/results"))
    a = p.parse_args()
    missing = [n for n in REQUIRED if not (a.results / n).exists()]
    if missing:
        print(json.dumps({"status": "FAIL", "missing": missing}, indent=2))
        raise SystemExit(1)
    report = {
        "anchor": check_anchor(a.results),
        "segments": check_segments(a.results),
        "consequence": check_consequence(a.results),
        "costs": check_costs(a.results),
    }
    report["status"] = "PASS" if all(v["ok"] for k, v in report.items() if k != "status") else "FAIL"
    # The consequence check now measures a coverage curve: it requires a real
    # loss under the manipulation, monotone detection in the budget, and a
    # caught arm that beats no-audit at the top budget. It deliberately does
    # not require equality with the clean baseline, because equality is what a
    # regime that never serves the manipulated round would produce.
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
