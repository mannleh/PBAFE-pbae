# -*- coding: utf-8 -*-
"""Compare VREFL verification-core results with the released PBA/3 bridge arms."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def load_rows(path):
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines()]


def mean_ci(values, resamples=20000, seed=55001):
    values = np.asarray(values, dtype=float)
    rng = np.random.default_rng(seed)
    means = values[rng.integers(0, len(values), size=(resamples, len(values)))].mean(axis=1)
    return {"mean": float(values.mean()), "ci95": np.quantile(means, [0.025, 0.975]).tolist(),
            "n": len(values)}


def summarize(vrefl_path: Path, pba_path: Path, resamples: int, seed: int,
              pba_full_path: Path | None = None):
    vr = load_rows(vrefl_path)
    pr = load_rows(pba_path)
    if pba_full_path is not None:
        pr += load_rows(pba_full_path)
    result = {"vrefl_rows": len(vr), "pba_rows": len(pr),
              "bootstrap": {"resamples": resamples, "seed": seed},
              "scenarios": {}}
    for scenario in ("mixed_recovery", "withholding_recovery"):
        block = {"methods": {}, "paired": {}}
        for method in ("noaudit", "uniform", "adaptive", "neutral", "separated", "pba_full", "vrefl_full"):
            rows = [r for r in (vr if method == "vrefl_full" else pr)
                    if r["scenario"] == scenario and r["method"] == method]
            rows.sort(key=lambda r: r["seed"])
            metrics = {
                "applied_violating_rounds": [r["bridge"]["applied_violating_rounds"] for r in rows],
                "compliant_rounds_retained": [r["bridge"]["compliant_rounds_retained"] for r in rows],
                "discarded_steps_fraction": [r["bridge"]["discarded_steps_fraction"] for r in rows],
                "f1": [r["final"]["f1"] for r in rows],
                "audit_total_bytes": [r["totals"]["audit_total_bytes"] for r in rows],
                "audit_cpu_ms": [r["totals"]["audit_cpu_ms"] for r in rows],
            }
            block["methods"][method] = {k: mean_ci(v, resamples, seed) for k, v in metrics.items()}
        by_seed = {}
        for method in ("noaudit", "uniform", "adaptive", "neutral", "separated", "pba_full", "vrefl_full"):
            rows = [r for r in (vr if method == "vrefl_full" else pr)
                    if r["scenario"] == scenario and r["method"] == method]
            by_seed[method] = {r["seed"]: r for r in rows}
        for other in ("noaudit", "uniform", "adaptive", "neutral", "separated", "pba_full"):
            for metric, section, key in (
                ("applied_violating_rounds", "bridge", "applied_violating_rounds"),
                ("compliant_rounds_retained", "bridge", "compliant_rounds_retained"),
                ("discarded_steps_fraction", "bridge", "discarded_steps_fraction"),
                ("f1", "final", "f1"),
                ("audit_total_bytes", "totals", "audit_total_bytes"),
            ):
                vals = [by_seed["vrefl_full"][s][section][key] - by_seed[other][s][section][key]
                        for s in sorted(by_seed["vrefl_full"])]
                block["paired"][f"vrefl_minus_{other}/{metric}"] = mean_ci(vals, resamples, seed)
        result["scenarios"][scenario] = block
    return result


def write_markdown(result, path: Path):
    lines = ["# VREFL verification-core comparison", "",
             f"VREFL runs: {result['vrefl_rows']}; PBA/3 bridge runs: {result['pba_rows']}.", "",
             "| scenario | method | applied violations | compliant retained | discard fraction | F1 | audit MB | audit CPU s |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for scenario, block in result["scenarios"].items():
        for method, metrics in block["methods"].items():
            lines.append(f"| {scenario} | {method} | "
                         f"{metrics['applied_violating_rounds']['mean']:.3f} | "
                         f"{metrics['compliant_rounds_retained']['mean']:.3f} | "
                         f"{metrics['discarded_steps_fraction']['mean']:.4f} | "
                         f"{metrics['f1']['mean']:.4f} | "
                         f"{metrics['audit_total_bytes']['mean']/1e6:.3f} | "
                         f"{metrics['audit_cpu_ms']['mean']/1000:.3f} |")
    lines += ["", "## Paired VREFL minus PBA/3 contrasts", "",
              "| scenario | contrast | mean | 95% CI |", "|---|---|---:|---:|"]
    for scenario, block in result["scenarios"].items():
        for name, obj in block["paired"].items():
            lo, hi = obj["ci95"]
            lines.append(f"| {scenario} | {name} | {obj['mean']:.4f} | [{lo:.4f}, {hi:.4f}] |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--vrefl", type=Path, default=Path(r".\experiments\external_vrefl\results_bridge\rows.jsonl"))
    p.add_argument("--pba", type=Path, default=Path(r".\experiments\pba_v3\results\bridge_v6_20261023\evaluation\rows.jsonl"))
    p.add_argument("--pba-full", type=Path, default=Path(r".\experiments\external_vrefl\results_pba_full\rows.jsonl"))
    p.add_argument("--resamples", type=int, default=20000)
    p.add_argument("--seed", type=int, default=55001)
    p.add_argument("--out", type=Path, default=Path(r".\experiments\external_vrefl\results_bridge\comparison_summary.json"))
    a = p.parse_args()
    result = summarize(a.vrefl, a.pba, a.resamples, a.seed, a.pba_full)
    a.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown(result, a.out.with_suffix(".md"))
    print(json.dumps({"out": str(a.out), "vrefl_rows": result["vrefl_rows"]}))


if __name__ == "__main__":
    main()
