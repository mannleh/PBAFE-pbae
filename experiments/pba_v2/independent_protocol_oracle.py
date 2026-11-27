#!/usr/bin/env python3
"""Independent semantic oracle for the released PBA/2 protocol fixtures.

This oracle deliberately does not import the verifier or derive expected labels
from verifier output.  The expected outcomes below are hand-authored from the
protocol's stated semantics and are compared with the emitted release JSON.
It is an outcome oracle, not a second cryptographic implementation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


EXPECTED = {
    "honest_round": ("PASS", "PASS", False, True),
    "update_replacement": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    "unsigned_insertion": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    "identity_exchange": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    "duplicate_record": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    "roster_omission": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    "unannounced_client": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    "modified_declared_count": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    # A valid signature authenticates a declaration; it does not establish
    # that the physical sample count is true.
    "signed_false_declared_count": ("PASS", "PASS", False, True),
    "rule_substitution": ("FAIL_POLICY", "FAIL_POLICY", False, False),
    "weight_inconsistency": ("FAIL_POLICY", "FAIL_POLICY", False, False),
    # A spot audit never reads the result object; full replay does.
    "forged_result": ("PASS", "FAIL_RESULT_REPLAY", False, False),
    "missing_evidence": ("INCONCLUSIVE_EVIDENCE", "INCONCLUSIVE_EVIDENCE", False, False),
    "old_round_replay": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    "forged_bulletin": ("FAIL_ROSTER", "FAIL_ROSTER", False, False),
    # Missing opening prevents a replay verdict, so availability remains
    # inconclusive even when a forged result is also present.
    "forged_result_plus_missing_opening": (
        "INCONCLUSIVE_EVIDENCE",
        "INCONCLUSIVE_EVIDENCE",
        False,
        False,
    ),
}


def evaluate(protocol: dict) -> dict:
    observed = {row["case"]: row for row in protocol["cases"]}
    rows = []
    for case, expected in EXPECTED.items():
        if case not in observed:
            rows.append({"case": case, "match": False, "reason": "missing case"})
            continue
        row = observed[case]
        exp_spot, exp_full, exp_spot_agg, exp_full_agg = expected
        checks = {
            "spot_outcome": row.get("record_outcome") == exp_spot,
            "full_outcome": row.get("full_outcome") == exp_full,
            "spot_aggregate_verified": row.get("record_aggregate_verified") == exp_spot_agg,
            "full_aggregate_verified": row.get("full_aggregate_verified") == exp_full_agg,
        }
        rows.append(
            {
                "case": case,
                "expected": {
                    "spot_outcome": exp_spot,
                    "full_outcome": exp_full,
                    "spot_aggregate_verified": exp_spot_agg,
                    "full_aggregate_verified": exp_full_agg,
                },
                "checks": checks,
                "match": all(checks.values()),
            }
        )
    extras = sorted(set(observed) - set(EXPECTED))
    if extras:
        rows.extend({"case": case, "match": False, "reason": "unexpected case"} for case in extras)
    return {
        "oracle": "PBA/2 semantic golden oracle v1",
        "oracle_scope": "outcome semantics only; not an independent cryptographic implementation",
        "case_count": len(observed),
        "expected_case_count": len(EXPECTED),
        "all_match": len(observed) == len(EXPECTED) and all(row["match"] for row in rows),
        "cases": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--protocol",
        type=Path,
        default=Path(__file__).resolve().parent / "results" / "release_v3" / "protocol_release.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "results" / "release_v3" / "protocol_oracle_release.json",
    )
    args = parser.parse_args()
    result = evaluate(json.loads(args.protocol.read_text(encoding="utf8")))
    args.output.write_text(json.dumps(result, indent=2), encoding="utf8")
    print(json.dumps(result, indent=2))
    if not result["all_match"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
