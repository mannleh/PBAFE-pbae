"""Generate the complete release_v4 macro file from the frozen artifacts.

The output contains the frozen release_v3 definitions (so existing manuscript
text keeps its numbers) followed by PBA/3 values, all read from JSON. Writing
the file whole removes the manual merge step that previously produced
duplicate and digit-named macros.

TeX macro names must be letters only: a digit terminates the control word, so
`\\PBA3Foo` is read as `\\PBA` followed by the characters `3Foo`.
"""
import json
from pathlib import Path

RESULTS = Path("experiments/pba_v3/results")
OUT = Path("submission_v4/experiments/pba_v2/results/release_v4/tex/result_macros.tex")

FROZEN_V3 = r"""% Auto-generated: frozen release_v3 definitions + PBA/3 values.
% Old names keep their release_v3 values so existing evaluation text is
% unchanged; PBA/3 alternatives use distinct letter-only names.
\newcommand{\PBASeedCount}{100}
\newcommand{\PBARecordBudget}{3}
\newcommand{\PBAAdaptivePersistentTDR}{0.921}
\newcommand{\PBAUniformPersistentTDR}{0.201}
\newcommand{\PBAPeriodicPersistentTDR}{0.115}
\newcommand{\PBAFullHighPersistentTDR}{1.000}
\newcommand{\PBAAdaptivePersistentBytes}{565500}
\newcommand{\PBAUniformPersistentBytes}{715741}
\newcommand{\PBAPeriodicPersistentBytes}{653178}
\newcommand{\PBAFullHighPersistentBytes}{6582452}
\newcommand{\PBAAdaptiveRandomTDR}{0.212}
\newcommand{\PBAWithholdingUniformInconclusive}{10.46}
\newcommand{\PBAAdaptivePersistentCoverage}{0.921}
\newcommand{\PBAUniformPersistentCoverage}{0.201}
\newcommand{\PBAAdaptiveLatencyDetected}{1.000}
\newcommand{\PBAUniformLatencyDetected}{1.000}
\newcommand{\PBAFLSeedCount}{3}
\newcommand{\PBAFOne}{0.7495}
\newcommand{\PBAFOneSD}{0.0078}
\newcommand{\PBAFBalancedAccuracy}{0.7144}
\newcommand{\PBAFBalancedAccuracySD}{0.0707}
\newcommand{\PBAFPrecision}{0.7532}
\newcommand{\PBAFRecall}{0.7697}
\newcommand{\PBAFTrainSeconds}{0.916}
\newcommand{\PBAFAuditSeconds}{0.948}
\newcommand{\PBAFAuditBytes}{6.501}
\newcommand{\PBAAuditMaxParamDiff}{0}
\newcommand{\PBASpotBytesDim}{11455}
\newcommand{\PBAFullBytesDim}{60455}
\newcommand{\PBASpotWallDim}{2.116}
\newcommand{\PBAFullWallDim}{4.434}
"""


def load(name):
    p = RESULTS / name
    if not p.exists():
        raise SystemExit(f"missing artifact: {p}")
    return json.loads(p.read_text(encoding="utf8"))


def m(name, value, fmt="{:.3f}"):
    if any(c.isdigit() for c in name):
        raise SystemExit(f"macro name may not contain digits: {name}")
    return f"\\newcommand{{\\{name}}}{{{fmt.format(value)}}}\n"


def main():
    a = load("a_manipulation_onset9.json")
    b = load("b_segment_v3.json")
    c = load("c_sweep_v1.json")
    t = load("tier_cost.json")
    S = {(x["schedule"], x["opponent"], x["workload"]): x for x in a["summary"]}

    def get(s, o, w, f):
        return S[(s, o, w)][f]

    lines = [FROZEN_V3, "\n% --- PBA/3: schedule manipulation (100 seeds, d=256, b=3, K=30) ---\n"]

    # withholding workload: the amplification and its repair
    la = get("adaptive", "withhold", "withholding", "inconclusive")
    ls = get("sealed_adaptive", "withhold", "withholding", "inconclusive")
    ln = get("sealed_navail", "withhold", "withholding", "inconclusive")
    lu = get("uniform", "withhold", "withholding", "inconclusive")
    for name, v in [("PBAAdaptiveWithholdInc", la), ("PBASealedWithholdInc", ls),
                    ("PBANavailWithholdInc", ln), ("PBAUniformWithholdInc", lu),
                    ("PBAWithholdRatio", la / lu)]:
        lines.append(m(name, v, "{:.2f}" if name == "PBAWithholdRatio" else "{:.2f}"))

    # coverage in the same workload (was hand-typed in the table)
    for name, key in [("PBACovUniformWithhold", ("uniform", "withhold", "withholding")),
                      ("PBACovAdaptiveWithhold", ("adaptive", "withhold", "withholding")),
                      ("PBACovSealedWithhold", ("sealed_adaptive", "withhold", "withholding")),
                      ("PBACovNavailWithhold", ("sealed_navail", "withhold", "withholding")),
                      ("PBACovRoundRobin", ("round_robin", "withhold", "withholding"))]:
        lines.append(m(name, get(*key, "coverage")))

    # opponent matrix at equal budget
    for name, key, field in [
        ("PBAMatrixPersistentUniform", ("uniform", "persistent", "persistent"), "tdr"),
        ("PBAMatrixPersistentFeedback", ("adaptive", "persistent", "persistent"), "tdr"),
        ("PBAMatrixPersistentNavail", ("sealed_navail", "persistent", "persistent"), "tdr"),
        ("PBAMatrixCopycatUniform", ("uniform", "copycat", "persistent"), "tdr"),
        ("PBAMatrixCopycatFeedback", ("adaptive", "copycat", "persistent"), "tdr"),
        ("PBAMatrixCopycatNavail", ("sealed_navail", "copycat", "persistent"), "tdr"),
        ("PBAMatrixSmartUniform", ("uniform", "withhold_smart", "persistent"), "tdr"),
        ("PBAMatrixSmartFeedback", ("adaptive", "withhold_smart", "persistent"), "tdr"),
        ("PBAMatrixSmartNavail", ("sealed_navail", "withhold_smart", "persistent"), "tdr"),
        ("PBAMatrixPredictUniform", ("uniform", "predictive", "persistent"), "tdr"),
        ("PBAMatrixPredictFeedback", ("adaptive", "predictive", "persistent"), "tdr"),
        ("PBAMatrixPredictSealed", ("sealed_adaptive", "predictive", "persistent"), "tdr"),
        ("PBAMatrixPredictNavail", ("sealed_navail", "predictive", "persistent"), "tdr"),
    ]:
        lines.append(m(name, get(*key, field)))

    # segment tier: worst deviation from the exact hypergeometric
    import math
    zmax = 0.0
    for r in b["summary"]:
        Sc, mm, bb, n = r["S"], r["m"], r["b"], r["n"]
        exact = math.comb(Sc - mm, bb) / math.comb(Sc, bb) if bb <= Sc - mm else 0.0
        sd = math.sqrt(max(exact * (1 - exact), 1e-9) / n)
        if sd:
            zmax = max(zmax, abs(r["miss_empirical"] - exact) / sd)
    lines.append(m("PBASegmentZMax", zmax, "{:.2f}"))
    lines.append(m("PBASegmentCells", len(b["summary"]), "{:d}"))

    # tier cost
    for name, dim, tier in [
        ("PBACostSmallRecordBytes", 256, "record"),
        ("PBACostSmallSegmentBytes", 256, "segment"),
        ("PBACostSmallFullBytes", 256, "full"),
        ("PBACostModelRecordBytes", 6241, "record"),
        ("PBACostModelSegmentBytes", 6241, "segment"),
        ("PBACostModelFullBytes", 6241, "full"),
    ]:
        lines.append(m(name, t["summary"][f"{dim}/{tier}"]["bytes"], "{:.0f}"))

    # consequence: the audit recovers a share of the loss that grows with budget
    cs = c["summary"]
    lines.append(m("PBAConsFClean", cs["clean"]["f1"]))
    lines.append(m("PBAConsFNoAudit", cs["no_audit"]["f1"]))
    lines.append(m("PBAConsFLoss", cs["clean"]["f1"] - cs["no_audit"]["f1"]))
    for bgt in sorted(cs["caught"], key=int):
        tag = {3: "Three", 10: "Ten", 30: "Thirty"}[int(bgt)]
        lines.append(m(f"PBAConsFBudget{tag}", cs["caught"][bgt]["f1"]))
        lines.append(m(f"PBAConsDetect{tag}", cs["caught"][bgt]["detection_rate"], "{:.2f}"))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(lines), encoding="utf8")
    print(json.dumps({"wrote": str(OUT), "macros": len(lines) - 1, "segment_z_max": round(zmax, 3)}))


if __name__ == "__main__":
    main()
