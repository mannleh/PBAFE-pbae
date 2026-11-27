# -*- coding: utf-8 -*-
"""E4 — cost-effectiveness synthesis (R1-6 / R3-5).

Reads the ALREADY-COMPLETED response summaries (no new training):
  * UNSW: decision_v5_20261022/response/summary.json  (six arms)
  * Edge-IIoTset: experiments/e1_edge/results/e1_edge_a*/summary.json (five arms)
and computes, per audited arm:
  contained violations, discarded training steps, audit traffic (MB),
  contained-per-discarded-step, contained-per-MB, and the containment–discard–traffic
  Pareto frontier. Emits E4_cost_effectiveness.csv, E4_rows.json and a PNG figure.
"""
import json
from pathlib import Path
import numpy as np

UNSW = Path(r".\experiments\pba_v3\results\decision_v5_20261022\response\summary.json")
E1ROOT = Path(r".\experiments\e1_edge\results")
OUT = Path(r".\experiments\e4_cost")
OUT.mkdir(parents=True, exist_ok=True)


def g(d, key):
    v = d.get(key)
    if isinstance(v, dict):
        return v.get("mean")
    return v


def arm_row(corpus, label, contained, discarded_steps, traffic_bytes, f1, n_seeds):
    mb = traffic_bytes / 1e6 if traffic_bytes else 0.0
    return {
        "corpus": corpus, "arm": label, "n_seeds": n_seeds,
        "contained_violations": contained,
        "discarded_steps": discarded_steps,
        "audit_traffic_MB": mb,
        "contained_per_discarded_step": (contained / discarded_steps) if discarded_steps and discarded_steps > 0 else None,
        "contained_per_MB": (contained / mb) if mb > 0 else None,
        "f1": f1,
    }


def unsw_rows():
    s = json.loads(UNSW.read_text(encoding="utf-8"))
    means, n = s["means"], s.get("n_seeds")
    base = g(means["drop_noaudit"], "attacked_updates_applied")
    rows = []
    for arm in ("drop_noaudit", "drop_uniform_b3", "drop_neutral_b3",
                "drop_separated_b3", "drop_full_b30"):
        m = means[arm]
        applied = g(m, "attacked_updates_applied")
        contained = (base - applied) if (base is not None and applied is not None) else None
        rows.append(arm_row("UNSW-NB15", arm, contained,
                            g(m, "discarded_training_steps"), g(m, "audit_total_bytes"),
                            g(m, "f1"), n))
    return rows


def edge_rows():
    rows = []
    for a in ("0.1", "0.5", "1.0"):
        p = E1ROOT / f"e1_edge_a{a}" / "summary.json"
        if not p.exists():
            continue
        s = json.loads(p.read_text(encoding="utf-8"))
        scen = "mixed_recovery"
        base = g(s["means"][f"{scen}/noaudit"], "applied_violating_rounds")
        for m in ("noaudit", "uniform", "adaptive", "neutral", "separated"):
            mm = s["means"][f"{scen}/{m}"]
            applied = g(mm, "applied_violating_rounds")
            contained = (base - applied) if (base is not None and applied is not None) else None
            rows.append(arm_row(f"Edge-IIoTset a={a}", m, contained,
                                g(mm, "discarded_training_steps"), g(mm, "audit_total_bytes"),
                                g(mm, "f1"), s.get("n_seeds")))
    return rows


def pareto(rows, corpus):
    # A point is on the frontier if no other point has >= containment, <= discarded steps
    # and <= traffic, with at least one strict improvement.
    pts = [r for r in rows if r["corpus"] == corpus and r["contained_violations"] is not None
           and r["arm"] not in ("drop_noaudit", "noaudit") and (r["discarded_steps"] or 0) > 0]
    front = []
    for p in pts:
        dominated = False
        for q in pts:
            if q is p:
                continue
            if (q["contained_violations"] >= p["contained_violations"]
                    and q["discarded_steps"] <= p["discarded_steps"]
                    and q["audit_traffic_MB"] <= p["audit_traffic_MB"]
                    and (q["contained_violations"] > p["contained_violations"]
                         or q["discarded_steps"] < p["discarded_steps"]
                         or q["audit_traffic_MB"] < p["audit_traffic_MB"])):
                dominated = True
                break
        if not dominated:
            front.append(p)
    return [f["arm"] for f in front]


def main():
    u = unsw_rows()
    e = edge_rows()
    rows = u + e
    for corpus in ("UNSW-NB15",) + tuple(sorted({r["corpus"] for r in e})):
        print(f"\n== {corpus}")
        print(f"{'arm':<24}{'contained':>11}{'discard_steps':>14}{'traffic_MB':>12}{'per_step':>10}{'per_MB':>9}{'f1':>8}")
        for r in rows:
            if r["corpus"] != corpus:
                continue
            def f(x, d=3):
                return f"{x:.{d}f}" if isinstance(x, (int, float)) else "NA"
            print(f"{r['arm']:<24}{f(r['contained_violations']):>11}{f(r['discarded_steps'],1):>14}"
                  f"{f(r['audit_traffic_MB']):>12}{f(r['contained_per_discarded_step']):>10}"
                  f"{f(r['contained_per_MB']):>9}{f(r['f1'],4):>8}")
        print("  Pareto frontier:", pareto(rows, corpus))
    (OUT / "E4_rows.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    # CSV
    keys = ["corpus", "arm", "n_seeds", "contained_violations", "discarded_steps",
            "audit_traffic_MB", "contained_per_discarded_step", "contained_per_MB", "f1"]
    lines = [",".join(keys)]
    for r in rows:
        lines.append(",".join(str(r[k]) if r[k] is not None else "" for k in keys))
    (OUT / "E4_cost_effectiveness.csv").write_text("\n".join(lines), encoding="utf-8")

    # Figure
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        corpora = ["UNSW-NB15"] + sorted({r["corpus"] for r in e})
        fig, axes = plt.subplots(1, len(corpora), figsize=(5.2 * len(corpora), 4.2), sharey=True)
        if len(corpora) == 1:
            axes = [axes]
        for ax, corpus in zip(axes, corpora):
            for r in rows:
                if r["corpus"] != corpus or r["contained_violations"] is None:
                    continue
                if r["arm"] in ("drop_noaudit", "noaudit"):
                    continue
                x = r["discarded_steps"]
                y = r["contained_violations"]
                s = 120 * max(0.3, r["audit_traffic_MB"])
                ax.scatter(x, y, s=s, alpha=.65)
                ax.annotate(r["arm"].replace("drop_", "").replace("_b3", "").replace("_b30", "(full)"),
                            (x, y), fontsize=7, xytext=(3, 3), textcoords="offset points")
            ax.set_title(corpus, fontsize=10)
            ax.set_xlabel("discarded training steps")
            ax.set_ylabel("violations contained")
            ax.grid(alpha=.3)
        fig.tight_layout()
        fig.savefig(OUT / "E4_pareto.png", dpi=170)
        print("\nwrote", OUT / "E4_pareto.png")
    except Exception as exc:
        print("figure skipped:", exc)


if __name__ == "__main__":
    main()