# -*- coding: utf-8 -*-
import json
import numpy as np
from pathlib import Path

p = Path(r".\experiments\e7_baselines\results\summary.json")
s = json.loads(p.read_text(encoding="utf-8"))
rows = s["rows"]
print("row keys:", sorted(rows[0].keys()))
print("rows:", len(rows), "semantic checks:", s.get("semantic_checks"))
m = s["means"]
METHODS = s["methods"]
scen = ["honest", "integrity_only", "mixed", "recovery", "moving_integrity", "moving_mixed", "withholding_only"]


def fmt(x, d=4):
    return "NA" if x is None else f"{x:.{d}f}"


print("\nintegrity TDR / audit KB")
print("%-18s" % "scenario" + "".join("%20s" % k for k in METHODS))
for sc in scen:
    print("%-18s" % sc, end="")
    for k in METHODS:
        r = m.get(f"{sc}/{k}", {})
        tdr = (r.get("integrity_tdr") or {}).get("mean")
        by = (r.get("bytes") or {}).get("mean")
        by = None if by is None else by / 1e3
        print("%20s" % f"{fmt(tdr)}/{fmt(by, 0)}", end="")
    print()

print("\ndiscarded fraction / F1")
for sc in ("mixed", "moving_integrity"):
    print("--", sc)
    for k in METHODS:
        r = m.get(f"{sc}/{k}", {})
        df = (r.get("discarded_fraction") or {}).get("mean")
        f1 = (r.get("f1") or {}).get("mean")
        cp = (r.get("compliant_retained") or {}).get("mean")
        print(f"  {k:<12} discard={fmt(df)} f1={fmt(f1)} compliant_retained={fmt(cp)}")


def paired(sc, a, b, key="integrity_tdr", n=20000, seed=77001):
    """bootstrap CI for mean(a) - mean(b) over matched seeds."""
    by_seed = {}
    for r in rows:
        if r["scenario"] == sc and r["method"] in (a, b):
            by_seed.setdefault(r["seed"], {})[r["method"]] = r.get(key)
    diffs = [v[a] - v[b] for v in by_seed.values() if v.get(a) is not None and v.get(b) is not None]
    if len(diffs) < 5:
        return None
    d = np.asarray(diffs)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(d), (n, len(d)))
    boot = d[idx].mean(1)
    return d.mean(), np.percentile(boot, [1.25, 98.75]), len(d), (d > 0).mean()


print("\npaired vs neutral (bootstrap 97.5% CI)")
for sc in scen:
    for k in ("uniform", "adaptive", "separated", "ucb", "epsgreedy"):
        for key in ("integrity_tdr",):
            res = paired(sc, "neutral", k, key)
            if res:
                print(f"{sc}/{k:<10} neutral-{k:<10} {res[0]:+.4f} [{res[1][0]:+.4f},{res[1][1]:+.4f}] n={res[2]} P(win)={res[3]:.2f}")

print("\nbytes neutral - competitor (MB)")
for sc in scen:
    for k in ("uniform", "adaptive", "separated", "ucb", "epsgreedy"):
        res = paired(sc, "neutral", k, "bytes")
        if res:
            print(f"{sc}/{k:<10} {res[0]/1e6:+.3f} MB [{res[1][0]/1e6:+.3f},{res[1][1]/1e6:+.3f}]")

print("\ncrowd-out:", s.get("crowdout"))
