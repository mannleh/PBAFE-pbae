# -*- coding: utf-8 -*-
"""E13 - feasibility envelope under edge-network conditions (R3-9).

Inputs are measured, not modelled: local compute, per-round bytes and request
counts come from E2b (d = 256, K = 30/100/200) and E2c (d = 6,241/49,921/99,841,
K = 30/100). The network term is analytic: sequential request/response over RTT
plus one RTO per lost request, with RTO = 200 ms. No kernel netem, no on-device
measurement: the output is a feasibility calculation.

A per-round compute model cpu = a + c*(b*d) + e*K is fitted on E2c and checked
leave-one-out; it is used only to interpolate between measured anchors.
"""
import csv, json, math
from pathlib import Path

import numpy as np

BASE = Path(r".\experiments")
OUT = BASE / "e13_envelope"
RTO_MS = 200.0


def load_points():
    pts = []
    for r in json.loads((BASE / "e2c_dimension" / "E2c_results.json").read_text(encoding="utf-8")):
        pts.append({"src": "E2c", "K": r["K"], "d": r["dimension"], "b": r["budget"],
                    "cpu": r["cpu_ms"], "bytes": r["bytes"], "req": r["requests"]})
    for r in json.loads((BASE / "e2_scaling" / "E2_results.json").read_text(encoding="utf-8")):
        pts.append({"src": "E2b", "K": r["K"], "d": 256, "b": r["budget"],
                    "cpu": r["cpu_ms_mean"], "bytes": r["bytes_mean"], "req": r["requests_mean"]})
    return pts


def fit(pts):
    X = np.array([[1.0, p["b"] * p["d"] / 1e6, p["K"] / 100.0] for p in pts])
    y = np.array([p["cpu"] for p in pts])
    coef, *_ = np.linalg.lstsq(X, y, rcond=None)
    # leave-one-out
    loo = []
    for i in range(len(pts)):
        m = np.ones(len(pts), bool); m[i] = False
        c2, *_ = np.linalg.lstsq(X[m], y[m], rcond=None)
        pred = float(np.dot(X[i], c2))
        loo.append(abs(pred - y[i]) / y[i])
    return coef, max(loo), float(np.mean(loo))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    pts = load_points()
    coef, loo_max, loo_mean = fit(pts)
    rows = []
    for p in pts:
        for rtt in (1, 5, 10, 20, 50, 100, 200):
            for loss in (0.001, 0.01, 0.05, 0.10):
                net = p["req"] * rtt + p["req"] * loss * RTO_MS
                total = p["cpu"] + net
                rows.append({"source": p["src"], "K": p["K"], "dimension": p["d"],
                             "budget": p["b"], "cpu_ms": round(p["cpu"], 1),
                             "requests": round(p["req"], 1), "rtt_ms": rtt, "loss": loss,
                             "network_ms": round(net, 1), "total_ms": round(total, 1),
                             "fits_1s": total <= 1000, "fits_5s": total <= 5000})
    with (OUT / "envelope.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)

    # largest RTT that still fits a 1 s / 5 s round, at 1% loss
    max_rtt, max_rtt5 = {}, {}
    for p in pts:
        key = f"K{p['K']}/d{p['d']}/b{p['b']}"
        ok = [r["rtt_ms"] for r in rows
              if r["K"] == p["K"] and r["dimension"] == p["d"] and r["budget"] == p["b"]
              and r["loss"] == 0.01 and r["fits_1s"]]
        ok5 = [r["rtt_ms"] for r in rows
               if r["K"] == p["K"] and r["dimension"] == p["d"] and r["budget"] == p["b"]
               and r["loss"] == 0.01 and r["fits_5s"]]
        max_rtt[key] = max(ok) if ok else 0
        max_rtt5[key] = max(ok5) if ok5 else 0
    summary = {
        "compute_model": {"intercept_ms": coef[0], "per_b_d_million": coef[1], "per_K_over_100": coef[2]},
        "leave_one_out_rel_err": {"max": loo_max, "mean": loo_mean},
        "rto_ms": RTO_MS,
        "max_rtt_fitting_1s_at_1pct_loss": max_rtt,
        "max_rtt_fitting_5s_at_1pct_loss": max_rtt5,
        "envelope_rows": len(rows),
        "feasible_1s_fraction": sum(r["fits_1s"] for r in rows) / len(rows),
        "feasible_5s_fraction": sum(r["fits_5s"] for r in rows) / len(rows),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    for key, rtt in max_rtt.items():
        sel = [r for r in rows if r["loss"] == 0.01 and r["rtt_ms"] == rtt
               and f"K{r['K']}/d{r['dimension']}/b{r['budget']}" == key]
        if sel:
            print(key, "max_rtt", rtt, "total", sel[0]["total_ms"])


if __name__ == "__main__":
    main()
