# -*- coding: utf-8 -*-
"""Cell-level aggregation and two-way cluster bootstrap for E1-L."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def boot_two_way(grid: dict[tuple[int, int], float], resamples: int, seed: int):
    samples = sorted({s for s, _ in grid})
    parts = sorted({p for _, p in grid})
    if len(grid) != len(samples) * len(parts):
        raise ValueError("two-way bootstrap expects a complete sample x partition grid")
    matrix = np.asarray([[grid[(s, p)] for p in parts] for s in samples], dtype=np.float64)
    rng = np.random.default_rng(seed)
    si = rng.integers(0, len(samples), size=(resamples, len(samples)))
    pi = rng.integers(0, len(parts), size=(resamples, len(parts)))
    out = matrix[si[:, :, None], pi[:, None, :]].mean(axis=(1, 2))
    vals = matrix.ravel()
    return {
        "n_cells": len(vals), "mean": float(vals.mean()),
        "sd_across_cells": float(vals.std(ddof=1)) if len(vals) > 1 else 0.0,
        "min": float(vals.min()), "max": float(vals.max()),
        "ci95": np.quantile(out, [0.025, 0.975]).tolist(),
        "cell_values": {f"s{s}_p{p}": v for (s, p), v in sorted(grid.items())},
    }


def summarize(root: Path, resamples: int, seed: int):
    cells = []
    for cfg_path in sorted(root.glob("*/config.json")):
        summary_path = cfg_path.with_name("summary.json")
        if not summary_path.exists():
            continue
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        cells.append((cfg, summary, cfg_path.parent))
    if not cells:
        raise ValueError(f"no completed cells under {root}")

    result = {"root": str(root.resolve()), "n_cells": len(cells),
              "n_runs": sum(s["n_runs"] for _, s, _ in cells),
              "cluster_bootstrap": {"resamples": resamples, "seed": seed,
                                    "unit": "sample seed x partition seed cell"},
              "alphas": {}}
    for alpha in sorted({cfg["alpha"] for cfg, _, _ in cells}):
        subset = [(cfg, s, d) for cfg, s, d in cells if cfg["alpha"] == alpha]
        block = {"n_cells": len(subset), "n_runs": sum(s["n_runs"] for _, s, _ in subset),
                 "methods": {}, "contrasts": {}}
        for scenario in ("mixed_recovery", "withholding_recovery"):
            for method in ("noaudit", "uniform", "adaptive", "neutral", "separated"):
                metrics = ("applied_violating_rounds", "compliant_rounds_retained",
                           "discarded_steps_fraction", "audit_total_bytes", "f1",
                           "precision", "recall", "balanced_accuracy")
                for metric in metrics:
                    grid = {}
                    for cfg, summary, _ in subset:
                        grid[(cfg["sample_seed"], cfg["partition_seed"])] = \
                            summary["means"][f"{scenario}/{method}"][metric]["mean"]
                    block["methods"][f"{scenario}/{method}/{metric}"] = boot_two_way(
                        grid, resamples, seed)

        contrasts = {
            "mixed_neutral_minus_uniform_applied": ("mixed_recovery", "neutral", "uniform",
                                                     "applied_violating_rounds"),
            "mixed_neutral_minus_noudit_f1": ("mixed_recovery", "neutral", "noaudit", "f1"),
            "mixed_neutral_minus_adaptive_compliant": ("mixed_recovery", "neutral", "adaptive",
                                                        "compliant_rounds_retained"),
            "withholding_neutral_minus_adaptive_compliant": ("withholding_recovery", "neutral",
                                                              "adaptive", "compliant_rounds_retained"),
        }
        for name, (scenario, a, b, metric) in contrasts.items():
            grid = {}
            for cfg, summary, _ in subset:
                av = summary["means"][f"{scenario}/{a}"][metric]["mean"]
                bv = summary["means"][f"{scenario}/{b}"][metric]["mean"]
                grid[(cfg["sample_seed"], cfg["partition_seed"])] = av - bv
            block["contrasts"][name] = boot_two_way(grid, resamples, seed)
        result["alphas"][str(alpha)] = block
    return result


def write_markdown(result, path: Path):
    lines = ["# E1-L summary", "",
             f"Cells: {result['n_cells']}; runs: {result['n_runs']}; "
             f"bootstrap resamples: {result['cluster_bootstrap']['resamples']}.", "",
             "Intervals use a two-way cluster bootstrap over sample-seed x partition-seed cells.", "",
             "| alpha | arm | applied violations | F1 | discard fraction | audit MB |",
             "|---|---:|---:|---:|---:|---:|"]
    for alpha, block in result["alphas"].items():
        for method in ("noaudit", "uniform", "adaptive", "neutral", "separated"):
            def cell(metric):
                return block["methods"][f"mixed_recovery/{method}/{metric}"]["mean"]
            lines.append(f"| {alpha} | {method} | {cell('applied_violating_rounds'):.3f} | "
                         f"{cell('f1'):.4f} | {cell('discarded_steps_fraction'):.4f} | "
                         f"{cell('audit_total_bytes')/1e6:.3f} |")
    lines += ["", "## Cluster-bootstrap contrasts", "",
              "| alpha | contrast | mean | 95% CI |", "|---|---|---:|---:|"]
    for alpha, block in result["alphas"].items():
        for name, obj in block["contrasts"].items():
            lo, hi = obj["ci95"]
            lines.append(f"| {alpha} | {name} | {obj['mean']:.4f} | [{lo:.4f}, {hi:.4f}] |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("root", type=Path)
    p.add_argument("--resamples", type=int, default=20000)
    p.add_argument("--seed", type=int, default=51001)
    p.add_argument("--out", type=Path, default=None)
    a = p.parse_args()
    result = summarize(a.root, a.resamples, a.seed)
    out = a.out or a.root / "pilot_summary.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown(result, out.with_suffix(".md"))
    print(json.dumps({"out": str(out), "cells": result["n_cells"], "runs": result["n_runs"]}))


if __name__ == "__main__":
    main()
