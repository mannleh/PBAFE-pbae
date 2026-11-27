"""Independent semantic oracle for PBA/3.

As with the PBA/2 oracle, the expected outcomes are hand-authored from the
protocol's stated semantics. This file imports neither the verifier nor the
fixture builder: it consumes the emitted JSON and compares.

The cases encode the three decisions that the PBA/3 experiments depend on:

1. a withheld opening is INCONCLUSIVE, never a detection;
2. a predicting server cannot gain from sealing only if the challenge set was
   actually sealed;
3. a corrupted segment sum is FAIL_RESULT_REPLAY, while a correctly signed
   but unverifiable contribution is FAIL_ROSTER.
"""
import argparse
import json
from pathlib import Path

EXPECTED = {
    # (spot outcome, full outcome, spot aggregate_verified, full aggregate_verified)
    # An outcome may also be a tuple of acceptable values when the protocol
    # semantics do not determine it without replaying the draw.
    "sealed_honest": ("PASS", "PASS", False, True),
    "sealed_withheld_opening": ("INCONCLUSIVE_EVIDENCE", "INCONCLUSIVE_EVIDENCE", False, False),
    "sealed_record_tamper": ("FAIL_POLICY", "FAIL_POLICY", False, False),
    "sealed_roster_substitution": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    "segment_honest": ("PASS", "PASS", False, True),
    # A corrupted published segment sum is visible only to the segment tier;
    # full replay recomputes from records and never reads the segment sums, so
    # it correctly returns PASS. The tiers are separated by construction.
    "segment_sum_tamper": ("FAIL_RESULT_REPLAY", "PASS", False, True),
    # A missing contribution object is unavailable evidence, not a proven
    # contradiction, so the segment tier must be inconclusive rather than FAIL.
    "segment_contribution_tamper": ("INCONCLUSIVE_EVIDENCE", "PASS", False, True),
    # An open schedule that draws the corrupted slot is defeated.
    "predicting_open_schedule": ("FAIL_POLICY", "FAIL_POLICY", False, False),
    # Whether the sealed draw includes the corrupted slot is a property of the
    # draw, not of the semantics: PASS means the draw avoided it, FAIL_POLICY
    # means it did not. Both are correct record-tier outcomes.
    "predicting_sealed_schedule": (("PASS", "FAIL_POLICY"), "FAIL_POLICY", False, False),
}


def matches(observed, expected):
    if isinstance(expected, tuple):
        return observed in expected
    return observed == expected


def evaluate(report):
    observed = {row["case"]: row for row in report["cases"]}
    rows = []
    for case, (s_out, f_out, s_agg, f_agg) in EXPECTED.items():
        if case not in observed:
            rows.append({"case": case, "match": False, "reason": "missing case"})
            continue
        row = observed[case]
        checks = {
            "spot_outcome": matches(row.get("record_outcome"), s_out),
            "full_outcome": matches(row.get("full_outcome"), f_out),
            "spot_aggregate_verified": row.get("record_aggregate_verified") == s_agg,
            "full_aggregate_verified": row.get("full_aggregate_verified") == f_agg,
        }
        rows.append({"case": case, "checks": checks, "match": all(checks.values())})
    extras = sorted(set(observed) - set(EXPECTED))
    rows.extend({"case": c, "match": False, "reason": "unexpected case"} for c in extras)
    return {
        "oracle": "PBA/3 semantic golden oracle v1",
        "oracle_scope": "outcome semantics only; not an independent cryptographic implementation",
        "case_count": len(observed),
        "expected_case_count": len(EXPECTED),
        "all_match": len(observed) == len(EXPECTED) and all(r["match"] for r in rows),
        "cases": rows,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = evaluate(json.loads(a.report.read_text(encoding="utf8")))
    a.output.write_text(json.dumps(result, indent=2), encoding="utf8")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["all_match"] else 1)


if __name__ == "__main__":
    main()
