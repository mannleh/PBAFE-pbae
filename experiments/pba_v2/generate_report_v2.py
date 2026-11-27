#!/usr/bin/env python3
"""Generate reproducible, manuscript-ready artifacts from PBA/2 release candidates.

This script never hand-copies experimental numbers. It merges the two host runs,
validates disjoint seeds and common configuration, derives byte-component totals
from per-audit verifier receipts, and emits CSV/JSON/TeX/PNG artifacts.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
from datetime import date
import platform
import shutil
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "experiments" / "pba_v2" / "results"
OUT = RESULTS / "release_v2"
HOSTS = {
    "10.248.144.223": RESULTS / "remote_223" / "budget" / "budget_audit_results_release.json",
    "10.248.144.224": RESULTS / "remote_224" / "budget" / "budget_audit_results_release.json",
}
FL_PATH = RESULTS / "fl_release_candidate_roster_v6.json"
PROTOCOL_PATH = RESULTS / "protocol_release_candidate_v3" / "protocol_attack_matrix_final.json"
TRANSFER_PATH = RESULTS / "transfer_client_45700.json"
LITERATURE_PATH = ROOT / "experiments" / "pba_v2" / "LITERATURE_MATRIX_PBA2_FINAL_2026-09-15.md"

COMPONENTS = (
    "bulletin_bytes_read", "snapshot_bytes_read", "policy_bytes_read",
    "roster_bytes_read", "state_bytes_read", "receipt_bytes_read",
    "merkle_proof_bytes_read", "opening_bytes_read", "update_bytes_read",
    "result_bytes_read", "disposition_bytes_read",
    "unattributed_framing_bytes",
)
SUMMARY_METRICS = (
    "record_level_tdr", "full_round_tdr", "bytes_read", "cpu_ms", "wall_ms",
    "first_detection_latency", "inconclusive", "checks", "full_round_checks",
    "records_processed", "updates_processed", *COMPONENTS,
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def mean_sd_ci(values):
    a = np.asarray(values, dtype=float)
    if a.size == 0:
        return 0.0, 0.0, 0.0
    mean = float(a.mean())
    sd = float(a.std(ddof=1)) if a.size > 1 else 0.0
    ci = float(1.96 * sd / math.sqrt(a.size)) if a.size > 1 else 0.0
    return mean, sd, ci


def collect_components(row):
    totals = {key: 0 for key in COMPONENTS}
    for audit_row in (row.get("audit_outcomes") or {}).values():
        itemized = 0
        for key in COMPONENTS:
            if key == "unattributed_framing_bytes":
                continue
            value = int(audit_row.get(key, 0) or 0)
            totals[key] += value
            itemized += value
        # Older remote runners serialized the verifier's per-object byte
        # fields but not request/framing counters. Preserve the exact total
        # and label the remainder instead of silently dropping it.
        totals["unattributed_framing_bytes"] += max(0, int(audit_row.get("total_network_bytes", 0) or 0) - itemized)
    return totals


def read_budget_rows():
    all_rows = []
    configs = []
    trace_keys_by_host = defaultdict(set)
    seen_seeds = set()
    provenance = []
    for host, path in HOSTS.items():
        if not path.exists():
            raise FileNotFoundError(path)
        data = json.loads(path.read_text(encoding="utf8"))
        configs.append(data["configuration"])
        provenance.append({"host": host, "path": str(path), "sha256": sha256(path)})
        for row in data["rows"]:
            seed = int(row["seed"])
            trace_keys_by_host[host].add((row["attack"], seed))
            seen_seeds.add(seed)
            enriched = dict(row)
            enriched["host"] = host
            enriched["source_file"] = str(path)
            enriched.update(collect_components(row))
            # The verifier's total is authoritative; this is a consistency check.
            component_total = sum(enriched[key] for key in COMPONENTS)
            if component_total != int(row["bytes_read"]):
                raise ValueError(f"byte accounting mismatch for row {host}/{seed}/{row['method']}/{row['attack']}: {component_total} != {row['bytes_read']}")
            all_rows.append(enriched)
    if len(configs) != 2:
        raise ValueError("expected two remote budget configurations")
    normalized = [{k: v for k, v in cfg.items() if k not in ("seeds", "seed_start")} for cfg in configs]
    if normalized[0] != normalized[1]:
        raise ValueError("remote budget configurations differ outside seed partition")
    if trace_keys_by_host[list(HOSTS)[0]].intersection(trace_keys_by_host[list(HOSTS)[1]]):
        raise ValueError("remote hosts contain overlapping attack traces")
    all_rows.sort(key=lambda x: (x["attack"], x["method"], int(x["seed"])))
    return all_rows, configs[0], provenance


def write_csv(path: Path, rows):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def aggregate(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["attack"], row["method"])].append(row)
    summary = []
    for (attack, method), group in sorted(grouped.items()):
        item = {"attack": attack, "method": method, "n": len(group), "hosts": sorted({x["host"] for x in group})}
        for key in SUMMARY_METRICS:
            m, sd, ci = mean_sd_ci([float(x.get(key, 0) or 0) for x in group])
            item[f"{key}_mean"] = m
            item[f"{key}_sd"] = sd
            item[f"{key}_95ci"] = ci
        summary.append(item)
    return summary


def tex_escape(value):
    return str(value).replace("_", r"\_").replace("%", r"\%").replace("&", r"\&")


def write_tex_fragments(summary, protocol, fl_data, transfer):
    tex = OUT / "tex"
    tex.mkdir(parents=True, exist_ok=True)
    # Main budget table: the caption fixes n=100, so the redundant sample-count
    # column is omitted. Short headings keep the table legible without scaling.
    keep_methods = ("uniform", "round_robin", "adaptive", "periodic_full", "fixed_high", "policy_blind")
    method_labels = {
        "uniform": "Uniform", "round_robin": "Round-robin", "adaptive": "Adaptive",
        "periodic_full": "Periodic full", "fixed_high": "Fixed-high", "policy_blind": "Policy-blind",
    }
    lines = [r"\begin{tabular}{llrrrrr}", r"\toprule", r"Attack & Method & TDR & CI & MB & CPU (s) & Inc. \\", r"\midrule"]
    for item in summary:
        if item["method"] not in keep_methods:
            continue
        tdr_key = "full_round_tdr" if item["method"] in ("periodic_full", "fixed_high") else "record_level_tdr"
        lines.append("{} & {} & {:.3f} & {:.3f} & {:.3f} & {:.3f} & {:.2f}".format(
            tex_escape(item["attack"].title()), tex_escape(method_labels[item["method"]]),
            item[f"{tdr_key}_mean"], item[f"{tdr_key}_95ci"],
            item["bytes_read_mean"] / 1e6, item["cpu_ms_mean"] / 1000,
            item["inconclusive_mean"]))
        lines[-1] += r"\\"
    lines += [r"\bottomrule", r"\end{tabular}"]
    (tex / "budget_summary.tex").write_text("\n".join(lines) + "\n", encoding="utf8")

    # Protocol table directly generated from protocol JSON. Outcomes are
    # abbreviated in the table and expanded in the manuscript caption.
    outcome_labels = {
        "PASS": "P", "FAIL_ROSTER": "R", "FAIL_POLICY": "Pol",
        "FAIL_RESULT_REPLAY": "Res", "INCONCLUSIVE_EVIDENCE": "I",
    }
    lines = [r"\begin{tabular}{>{\raggedright\arraybackslash}p{0.27\textwidth}ccrrrr}", r"\toprule", r"Case & Spot & Full & Spot B & Full B & Spot upd. & Full upd. \\", r"\midrule"]
    for row in protocol["cases"]:
        lines.append("{} & {} & {} & {} & {} & {} & {}".format(
            tex_escape(row["case"].replace("_", " ")),
            outcome_labels[row["record_outcome"]], outcome_labels[row["full_outcome"]],
            row["record_bytes"], row["full_bytes"], row["record_updates_processed"], row["full_updates_processed"]))
        lines[-1] += r"\\"
    lines += [r"\bottomrule", r"\end{tabular}"]
    (tex / "protocol_matrix.tex").write_text("\n".join(lines) + "\n", encoding="utf8")

    # FL table.
    runs = fl_data["runs"]
    by_method = defaultdict(list)
    for row in runs:
        by_method[row["method"]].append(row)
    lines = [r"\begin{tabular}{lrrrrrr}", r"\toprule", r"Method & F1 & Bal. acc. & Precision & Recall & Audit bytes (MB) & $\Delta$ params \\", r"\midrule"]
    fl_summary = []
    for method in sorted(by_method):
        group = by_method[method]
        item = {"method": method}
        for key in ("f1", "balanced_accuracy", "precision", "recall", "total_audit_bytes", "max_parameter_difference"):
            item[key] = mean_sd_ci([float(x[key]) for x in group])
        fl_summary.append(item)
        lines.append("{} & {:.4f} & {:.4f} & {:.4f} & {:.4f} & {:.3f} & {:.3g}".format(
            tex_escape(method), item["f1"][0], item["balanced_accuracy"][0], item["precision"][0], item["recall"][0],
            item["total_audit_bytes"][0]/1e6, item["max_parameter_difference"][0]))
        lines[-1] += r"\\"
    lines += [r"\bottomrule", r"\end{tabular}"]
    (tex / "fl_summary.tex").write_text("\n".join(lines) + "\n", encoding="utf8")
    (OUT / "fl_summary.json").write_text(json.dumps(fl_summary, indent=2), encoding="utf8")

    # Network transfer table.
    by_dim_kind = defaultdict(list)
    for row in transfer:
        by_dim_kind[(int(row["dimension"]), row["kind"])].append(row)
    lines = [r"\begin{tabular}{rrr rrr}", r"\toprule", r"Dimension & Type & Payload (bytes) & Payload SD & Wall (ms) & Wall SD \\", r"\midrule"]
    transfer_summary = []
    for (dim, kind), group in sorted(by_dim_kind.items()):
        payload = mean_sd_ci([float(x["payload_bytes"]) for x in group])
        wall = mean_sd_ci([float(x["wall_ms"]) for x in group])
        transfer_summary.append({"dimension": dim, "kind": kind, "payload": payload, "wall": wall})
        lines.append("{} & {} & {:.0f} & {:.1f} & {:.3f} & {:.3f}".format(dim, kind, payload[0], payload[1], wall[0], wall[1]))
        lines[-1] += r"\\"
    lines += [r"\bottomrule", r"\end{tabular}"]
    (tex / "network_summary.tex").write_text("\n".join(lines) + "\n", encoding="utf8")
    (OUT / "network_summary.json").write_text(json.dumps(transfer_summary, indent=2), encoding="utf8")


def make_figures(summary, protocol, fl_data, transfer):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    figdir = OUT / "figures"
    figdir.mkdir(parents=True, exist_ok=True)
    colors = {"uniform": "#4C78A8", "round_robin": "#72B7B2", "adaptive": "#F58518", "periodic_full": "#E45756", "fixed_high": "#B279A2", "policy_blind": "#54A24B"}
    methods = ["uniform", "round_robin", "adaptive", "periodic_full", "fixed_high", "policy_blind"]
    attacks = ["random", "persistent", "withholding"]
    index = {(x["attack"], x["method"]): x for x in summary}

    # TDR bars with the explicitly correct metric per method.
    fig, axes = plt.subplots(1, 3, figsize=(13, 4), sharey=True)
    for ax, attack in zip(axes, attacks):
        vals = []
        cis = []
        for method in methods:
            item = index[(attack, method)]
            key = "full_round_tdr" if method in ("periodic_full", "fixed_high") else "record_level_tdr"
            vals.append(item[f"{key}_mean"]); cis.append(item[f"{key}_95ci"])
        bars = ax.bar(range(len(methods)), vals, yerr=cis, color=[colors[m] for m in methods], capsize=3)
        ax.set_title(attack.replace("_", " ").title())
        ax.set_xticks(range(len(methods)), [m.replace("_", "\n") for m in methods], rotation=0, fontsize=8)
        ax.set_ylim(0, 1.05); ax.grid(axis="y", alpha=.25)
        ax.set_ylabel("Detection rate" if ax is axes[0] else "")
    fig.suptitle("Equal-budget audit detection rate (100 seeds; bars show 95% CI)")
    fig.tight_layout()
    fig.savefig(figdir / "budget_tdr.png", dpi=220, bbox_inches="tight"); plt.close(fig)

    # Bytes read.
    fig, ax = plt.subplots(figsize=(8, 4.5))
    width=.12; x=np.arange(len(attacks))
    for j, method in enumerate(methods):
        vals=[index[(a,method)]["bytes_read_mean"]/1e6 for a in attacks]
        ax.bar(x+(j-2.5)*width, vals, width, label=method.replace("_", " "), color=colors[method])
    ax.set_xticks(x, [a.title() for a in attacks]); ax.set_ylabel("Total bytes read (MB)")
    ax.set_title("Verification traffic under identical attack traces")
    ax.legend(ncol=3, fontsize=8); ax.grid(axis="y", alpha=.25); fig.tight_layout()
    fig.savefig(figdir / "budget_bytes.png", dpi=220, bbox_inches="tight"); plt.close(fig)

    # First detection latency for persistent attacker.
    fig, ax = plt.subplots(figsize=(8, 4.5))
    vals=[]; cis=[]; labels=[]
    for method in methods:
        item=index[("persistent",method)]; vals.append(item["first_detection_latency_mean"]); cis.append(item["first_detection_latency_95ci"]); labels.append(method.replace("_", "\n"))
    ax.bar(range(len(methods)), vals, yerr=cis, color=[colors[m] for m in methods], capsize=3)
    ax.set_xticks(range(len(methods)), labels); ax.set_ylabel("Rounds from attack onset")
    ax.set_title("Persistent attacker: first-detection latency (95% CI)"); ax.grid(axis="y", alpha=.25); fig.tight_layout()
    fig.savefig(figdir / "persistent_latency.png", dpi=220, bbox_inches="tight"); plt.close(fig)

    # Evidence withholding: inconclusive outcomes.
    fig, ax = plt.subplots(figsize=(8, 4.5))
    vals=[]; cis=[]
    for method in methods:
        item=index[("withholding",method)]; vals.append(item["inconclusive_mean"]); cis.append(item["inconclusive_95ci"])
    ax.bar(range(len(methods)), vals, yerr=cis, color=[colors[m] for m in methods], capsize=3)
    ax.set_xticks(range(len(methods)), [m.replace("_", "\n") for m in methods]); ax.set_ylabel("Inconclusive audit calls")
    ax.set_title("Evidence-withholding attacker: explicit inconclusive outcomes"); ax.grid(axis="y", alpha=.25); fig.tight_layout()
    fig.savefig(figdir / "withholding_inconclusive.png", dpi=220, bbox_inches="tight"); plt.close(fig)

    # Protocol spot/full traffic.
    names=[r["case"].replace("_", "\n") for r in protocol["cases"]]
    spot=[r["record_bytes"] for r in protocol["cases"]]; full=[r["full_bytes"] for r in protocol["cases"]]
    fig, ax = plt.subplots(figsize=(13, 5))
    x=np.arange(len(names)); ax.bar(x-.2, spot, .4, label="Record-level", color="#4C78A8"); ax.bar(x+.2, full, .4, label="Full replay", color="#E45756")
    ax.set_xticks(x,names,fontsize=7); ax.set_ylabel("Network bytes read"); ax.set_title("Protocol attack matrix: bounded spot audit vs full replay")
    ax.legend(); ax.grid(axis="y",alpha=.25); fig.tight_layout(); fig.savefig(figdir/"protocol_bytes.png",dpi=220,bbox_inches="tight"); plt.close(fig)

    # Network transfer.
    by=defaultdict(list)
    for row in transfer: by[(int(row["dimension"]),row["kind"])].append(row)
    fig, ax = plt.subplots(figsize=(7,4.5))
    for kind,color in (("spot","#4C78A8"),("full","#E45756")):
        dims=sorted({d for d,k in by if k==kind}); means=[]; cis=[]
        for d in dims:
            m,sd,ci=mean_sd_ci([x["wall_ms"] for x in by[(d,kind)]]); means.append(m); cis.append(ci)
        ax.errorbar(dims,means,yerr=cis,marker="o",capsize=3,label=kind,color=color)
    ax.set_xlabel("Vector dimension"); ax.set_ylabel("TCP transfer wall time (ms)"); ax.set_title("Controlled two-host transfer experiment")
    ax.grid(alpha=.25); ax.legend(); fig.tight_layout(); fig.savefig(figdir/"network_transfer.png",dpi=220,bbox_inches="tight"); plt.close(fig)

    # FL parameter preservation.
    by_method=defaultdict(list)
    for row in fl_data["runs"]: by_method[row["method"]].append(row)
    labels=sorted(by_method); means=[]; cis=[]
    for m in labels:
        vals=[x["max_parameter_difference"] for x in by_method[m]]; means.append(float(np.mean(vals))); cis.append(float(1.96*np.std(vals,ddof=1)/math.sqrt(len(vals))) if len(vals)>1 else 0)
    fig, ax=plt.subplots(figsize=(8,4.5)); ax.bar(range(len(labels)),means,yerr=cis,color="#59A14F",capsize=3)
    ax.set_xticks(range(len(labels)),[x.replace("_","\n") for x in labels]); ax.set_ylabel("Maximum parameter difference")
    ax.set_title("Matched FedAvg path: audit instrumentation difference"); ax.grid(axis="y",alpha=.25); fig.tight_layout(); fig.savefig(figdir/"fl_parameter_difference.png",dpi=220,bbox_inches="tight"); plt.close(fig)

    # Lightweight security-property matrix diagram (property-level, not performance).
    properties=["Update privacy","Roster consistency","Policy compliance","Final result consistency","Dropout evidence","Explicit inconclusive"]
    works=["FedAggVerify","Wu","EARVP","Niu","PBA/2"]
    matrix=np.array([
        [1,0,1,1,0], [1,0,0,0,1], [0,0,0,0,1], [1,0,1,1,1], [1,0,0,0,1], [0,0,0,0,1]
    ])
    fig,ax=plt.subplots(figsize=(8,4)); ax.imshow(matrix,cmap="Blues",vmin=0,vmax=1,aspect="auto")
    ax.set_xticks(range(len(works)),works); ax.set_yticks(range(len(properties)),properties)
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]): ax.text(j,i,"yes" if matrix[i,j] else "different",ha="center",va="center",fontsize=8,color="white" if matrix[i,j] else "black")
    ax.set_title("Property-level comparison; cells summarize scope, not performance")
    fig.tight_layout(); fig.savefig(figdir/"security_property_matrix.png",dpi=220,bbox_inches="tight"); plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rows, config, provenance = read_budget_rows()
    summary = aggregate(rows)
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf8"))
    fl_data = json.loads(FL_PATH.read_text(encoding="utf8"))
    transfer = json.loads(TRANSFER_PATH.read_text(encoding="utf8"))
    # Ensure the merged budget is genuinely 100 disjoint seeds and all expected cells exist.
    if len(rows) != 2400 or len({int(x["seed"]) for x in rows}) != 100:
        raise ValueError("expected 2,400 rows and 100 disjoint seeds")
    if len(summary) != 24:
        raise ValueError("expected 3 attacks x 8 methods")
    write_csv(OUT / "budget_release_merged.csv", rows)
    (OUT / "budget_release_merged.json").write_text(json.dumps({
        "status": "measured-candidate; two-host merged; pending final manuscript acceptance",
        "protocol": "PBA/2", "configuration": config,
        "provenance": provenance, "summary": summary,
        "row_count": len(rows), "seed_count": len({int(x["seed"]) for x in rows}),
    }, indent=2), encoding="utf8")
    (OUT / "protocol_release.json").write_text(json.dumps(protocol, indent=2), encoding="utf8")
    (OUT / "fl_release.json").write_text(json.dumps(fl_data, indent=2), encoding="utf8")
    (OUT / "transfer_release.json").write_text(json.dumps(transfer, indent=2), encoding="utf8")
    write_tex_fragments(summary, protocol, fl_data, transfer)
    make_figures(summary, protocol, fl_data, transfer)
    manifest={
        "generated_on": date.today().isoformat(),
        "status": "measured-candidate; independently reviewable; not yet claimed as accepted publication result",
        "script_sha256": sha256(Path(__file__)),
        "inputs": {
            "budget_hosts": provenance, "protocol": {"path": str(PROTOCOL_PATH), "sha256": sha256(PROTOCOL_PATH)},
            "fl": {"path": str(FL_PATH), "sha256": sha256(FL_PATH)},
            "transfer": {"path": str(TRANSFER_PATH), "sha256": sha256(TRANSFER_PATH)},
            "literature_matrix": {"path": str(LITERATURE_PATH), "sha256": sha256(LITERATURE_PATH)},
        },
        "constraints": {"old_cava_modified": False, "four_papers_run_as_performance_baselines": False,
                        "cross_host_timing_ranked": False, "record_level_claims_full_result": False},
        "outputs": [str(p.relative_to(ROOT)) for p in sorted(OUT.rglob("*")) if p.is_file()],
    }
    (OUT / "reproducibility_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")
    print(json.dumps({"out": str(OUT), "rows": len(rows), "seeds": 100, "summary_cells": len(summary), "figures": len(list((OUT/'figures').glob('*.png')))}, indent=2))


if __name__ == "__main__":
    main()
