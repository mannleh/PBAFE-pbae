"""P4.6: figures for the PBA/3 results.

Three panels the manuscript needs and does not yet have:
  fig_opponent_matrix   detection rate by opponent and schedule
  fig_withhold_amplify  inconclusive counts under withholding
  fig_tier_cost         bytes per tier at 256 and 6,241 dimensions
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RESULTS = Path("experiments/pba_v3/results")
OUT = Path("submission_v4/experiments/pba_v2/results/release_v4/figures")


def load(n):
    return json.loads((RESULTS / n).read_text(encoding="utf8"))


def save(fig, name):
    OUT.mkdir(parents=True, exist_ok=True)
    p = OUT / name
    fig.tight_layout()
    fig.savefig(p, dpi=300)
    fig.savefig(p.with_suffix(".pdf"))
    plt.close(fig)
    return p


def opponent_matrix():
    a = load("a_manipulation.json")
    S = {(x["schedule"], x["opponent"], x["workload"]): x for x in a["summary"]}
    sched = ["uniform", "adaptive", "sealed_adaptive", "sealed_navail"]
    opps = ["persistent", "copycat", "withhold_smart", "predictive"]
    labels = ["persistent", "copycat", "intermittent\nwithholding", "prediction"]
    wl = {"persistent": "persistent", "copycat": "persistent",
          "withhold_smart": "persistent", "predictive": "persistent"}
    grid = [[S[(s, o, wl[o])]["tdr"] for o in opps] for s in sched]
    fig, ax = plt.subplots(figsize=(5.4, 2.8))
    im = ax.imshow(grid, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(opps)), labels, fontsize=7)
    ax.set_yticks(range(len(sched)), ["uniform", "feedback", "sealed, a=0.5", "sealed, a=0"], fontsize=7)
    for i, row in enumerate(grid):
        for j, v in enumerate(row):
            ax.text(j, i, f"{v:.2f}", ha="center", va="center",
                    color="white" if v > 0.55 else "black", fontsize=7)
    fig.colorbar(im, ax=ax, fraction=0.035, pad=0.02, label="record-level TDR")
    ax.set_title("Detection by opponent and schedule (100 seeds, b=3)", fontsize=8)
    return save(fig, "fig_opponent_matrix.png")


def withhold_amplify():
    a = load("a_manipulation.json")
    S = {(x["schedule"], x["opponent"], x["workload"]): x for x in a["summary"]}
    names = ["uniform", "adaptive", "sealed_adaptive", "sealed_navail"]
    vals = [S[(s, "withhold", "withholding")]["inconclusive"] for s in names]
    errs = [S[(s, "withhold", "withholding")]["inconclusive_ci"] for s in names]
    fig, ax = plt.subplots(figsize=(3.4, 2.4))
    ax.bar(range(len(names)), vals, yerr=errs, capsize=2, color=["#777", "#c44", "#c88", "#48a"])
    ax.set_xticks(range(len(names)), ["uniform", "feedback", "sealed\na=0.5", "sealed\na=0"], fontsize=7)
    ax.set_ylabel("inconclusive verdicts per run", fontsize=7)
    ax.tick_params(labelsize=7)
    ax.set_title("Withholding: no scheduler detects", fontsize=8)
    return save(fig, "fig_withhold_amplify.png")


def tier_cost():
    t = load("tier_cost.json")["summary"]
    dims = [256, 6241]
    tiers = ["record", "segment", "full"]
    fig, ax = plt.subplots(figsize=(3.6, 2.4))
    width = 0.26
    for i, tier in enumerate(tiers):
        ax.bar([x + (i - 1) * width for x in range(len(dims))],
               [t[f"{d}/{tier}"]["bytes"] / 1e3 for d in dims],
               width=width, label=tier)
    ax.set_xticks(range(len(dims)), [f"d={d}" for d in dims], fontsize=7)
    ax.set_ylabel("bytes read (kB)", fontsize=7)
    ax.tick_params(labelsize=7)
    ax.legend(fontsize=6, frameon=False)
    ax.set_title("Per-tier cost, same fixture", fontsize=8)
    return save(fig, "fig_tier_cost.png")


if __name__ == "__main__":
    for f in (opponent_matrix(), withhold_amplify(), tier_cost()):
        print(f)
