# -*- coding: utf-8 -*-
"""Compact table from an E1 (or v6 bridge) summary.json."""
import json, sys
from pathlib import Path

KEYS = ["applied_violating_rounds", "prevented_violating_rounds", "compliant_rounds_retained",
        "discarded_steps_fraction", "f1", "audit_total_bytes"]


def show(folder):
    s = json.loads((Path(folder) / "summary.json").read_text(encoding="utf-8"))
    cfg = json.loads((Path(folder) / "config.json").read_text(encoding="utf-8"))
    print(f"== {Path(folder).name}  alpha={cfg.get('alpha')} seeds={s['n_seeds']} runs={s['n_runs']} dropped={cfg.get('dropped_clients')}")
    for scen in ("mixed_recovery", "withholding_recovery"):
        print(f" [{scen}]")
        print("  method      " + "".join(f"{k[:16]:>18}" for k in KEYS))
        for m in ("noaudit", "uniform", "adaptive", "neutral", "separated"):
            g = s["means"][f"{scen}/{m}"]
            cells = []
            for k in KEYS:
                v = g[k]["mean"]
                cells.append(f"{v:>18.4f}" if v is not None else f"{'NA':>18}")
            print(f"  {m:<11}" + "".join(cells))
    print(" paired mixed neutral-uniform applied_violating:",
          s["paired"]["mixed_recovery/neutral-uniform"]["applied_violating_rounds"])


if __name__ == "__main__":
    for f in sys.argv[1:]:
        show(f)