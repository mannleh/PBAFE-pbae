# -*- coding: utf-8 -*-
"""Summary for the paired Edge-IIoTset model-capacity stress test."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def boot_cells(grid: dict[tuple[int, int], float], resamples: int, seed: int):
    samples = sorted({s for s, _ in grid})
    parts = sorted({p for _, p in grid})
    if len(grid) != len(samples) * len(parts):
        raise ValueError("expected a complete sample x partition grid")
    matrix = np.asarray([[grid[(s, p)] for p in parts] for s in samples], dtype=np.float64)
    rng = np.random.default_rng(seed)
    si = rng.integers(0, len(samples), size=(resamples, len(samples)))
    pi = rng.integers(0, len(parts), size=(resamples, len(parts)))
    out = matrix[si[:, :, None], pi[:, None, :]].mean(axis=(1, 2))
    vals = matrix.ravel()
    return {
        "n_cells": len(vals), "mean": float(vals.mean()),
        "sd_across_cells": float(vals.std(ddof=1)) if len(vals) > 1 else 0.0,
        "ci95": np.quantile(out, [0.025, 0.975]).tolist(),
        "cell_values": {f"s{s}_p{p}": v for (s, p), v in sorted(grid.items())},
    }


def summarize(root: Path, resamples: int, seed: int):
    records = {}
    for cfg_path in sorted(root.glob("*/config.json")):
        summary_path = cfg_path.with_name("summary.json")
        if not summary_path.exists():
            continue
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        key = (cfg["sample_seed"], cfg["partition_seed"], cfg["alpha"], cfg["hidden"])
        records[key] = (cfg, summary, cfg_path.parent)
    widths = sorted({k[3] for k in records})
    if len(widths) != 2:
        raise ValueError(f"expected two widths, got {widths}")
    low, high = widths
    result = {
        "root": str(root.resolve()), "widths": {"low": low, "high": high},
        "low_params": next(c["model_params"] for c, _, _ in records.values() if c["hidden"] == low),
        "high_params": next(c["model_params"] for c, _, _ in records.values() if c["hidden"] == high),
        "n_cells_per_width": len(records) // 2,
        "n_runs": sum(s["n_runs"] for _, s, _ in records.values()),
        "cluster_bootstrap": {"resamples": resamples, "seed": seed,
                              "unit": "sample seed x partition seed cell"},
        "alphas": {},
    }
    for alpha in sorted({k[2] for k in records}):
        keys = sorted((s, p) for s, p, a, h in records if a == alpha and h == low)
        block = {"n_pairs": len(keys), "contrasts": {}, "by_width": {}}
        for hidden in (low, high):
            block["by_width"][str(hidden)] = {}
            for method in ("noaudit", "uniform", "adaptive", "neutral", "separated"):
                for metric in ("applied_violating_rounds", "compliant_rounds_retained",
                               "discarded_steps_fraction", "audit_total_bytes", "f1"):
                    grid = {(s, p): records[(s, p, alpha, hidden)][1]["means"]
                            [f"mixed_recovery/{method}"][metric]["mean"] for s, p in keys}
                    block["by_width"][str(hidden)][f"{method}/{metric}"] = boot_cells(
                        grid, resamples, seed)
        specs = {
            "high_minus_low_neutral_applied": ("neutral", "applied_violating_rounds"),
            "high_minus_low_neutral_f1": ("neutral", "f1"),
            "high_minus_low_neutral_discard": ("neutral", "discarded_steps_fraction"),
            "high_minus_low_neutral_audit_bytes": ("neutral", "audit_total_bytes"),
            "high_neutral_minus_uniform_applied": ("neutral-uniform", "applied_violating_rounds"),
            "high_neutral_minus_noudit_f1": ("neutral-noaudit", "f1"),
            "high_neutral_minus_adaptive_compliant": ("neutral-adaptive", "compliant_rounds_retained"),
        }
        for name, (kind, metric) in specs.items():
            grid = {}
            for s, p in keys:
                lo = records[(s, p, alpha, low)][1]["means"]
                hi = records[(s, p, alpha, high)][1]["means"]
                if kind == "neutral":
                    grid[(s, p)] = hi[f"mixed_recovery/neutral"][metric]["mean"] - \
                                   lo[f"mixed_recovery/neutral"][metric]["mean"]
                else:
                    left, right = kind.split("-")
                    grid[(s, p)] = hi[f"mixed_recovery/{left}"][metric]["mean"] - \
                                   hi[f"mixed_recovery/{right}"][metric]["mean"]
            block["contrasts"][name] = boot_cells(grid, resamples, seed)
        result["alphas"][str(alpha)] = block
    return result


def write_markdown(result, path: Path):
    lines = ["# Edge-IIoTset model-capacity stress test", "",
             f"Low-capacity model: {result['low_params']} parameters; "
             f"high-capacity model: {result['high_params']} parameters.", "",
             f"Paired cells per width: {result['n_cells_per_width']}; runs: {result['n_runs']}.", "",
             "| contrast | mean | 95% cluster-bootstrap CI |", "|---|---:|---:|"]
    for alpha, block in result["alphas"].items():
        for name, obj in block["contrasts"].items():
            lo, hi = obj["ci95"]
            lines.append(f"| α={alpha} {name} | {obj['mean']:.4f} | [{lo:.4f}, {hi:.4f}] |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("root", type=Path)
    p.add_argument("--resamples", type=int, default=20000)
    p.add_argument("--seed", type=int, default=54001)
    p.add_argument("--out", type=Path, default=None)
    a = p.parse_args()
    result = summarize(a.root, a.resamples, a.seed)
    out = a.out or a.root / "capacity_summary.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown(result, out.with_suffix(".md"))
    print(json.dumps({"out": str(out), "runs": result["n_runs"],
                      "low_params": result["low_params"], "high_params": result["high_params"]}))


if __name__ == "__main__":
    main()
