"""Bounded synthetic v6 regression and independent trace-validator tests.

Run with unittest, not pytest. No evaluation data or experiment jobs are run.
"""
import contextlib
import copy
import hashlib
import inspect
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from experiments.pba_v3 import v6_bridge as bridge
from experiments.pba_v3 import v6_bridge_validate as validator
from experiments.pba_v3.codec import SCALE
from experiments.pba_v3.repository import Keys
from experiments.pba_v3.v5_response import (
    build_training_fixture, next_model, published_aggregate, reject_round, run_arm,
)
from experiments.pba_v3.verify import FAIL_POLICY, INCONCLUSIVE, PASS, audit


def toy_data():
    rng = np.random.default_rng(144)
    X = rng.normal(size=(180, 3))
    y = np.tile([0, 1], 90)
    return ({"X_train": X, "y_train": y, "X_test": X[:40], "y_test": y[:40]},
            [list(range(i * 6, (i + 1) * 6)) for i in range(30)])


def fixture(active=False):
    chosen = [0, 13, 15]
    vectors = [np.array([1, -2, 3]), np.array([8, -3, 4]), np.array([-2, 7, 9])]
    counts = [10, 14, 16]
    aggregate = published_aggregate(vectors, counts, chosen, active)
    return build_training_fixture(np.zeros(3), vectors, counts, chosen, 30, 7,
                                  1, Keys.generate(range(30)), active, aggregate)


def strip_timings(value):
    if isinstance(value, dict):
        return {key: strip_timings(item) for key, item in value.items() if not key.endswith("_ms")}
    if isinstance(value, list):
        return [strip_timings(item) for item in value]
    return value


class BridgeSemanticsTests(unittest.TestCase):
    def test_accepted_opening_withholding_is_inconclusive(self):
        f = fixture()
        before = {key: value for key, value in f.source.items() if key != "record/0/opening"}
        removed = bridge.withhold(f, [0])
        self.assertEqual(removed, ["record/0/opening"])
        self.assertEqual(f.source, before)  # candidate and commitments are untouched
        result = audit(f.source, f.trust, slots=[0, 2, 3])
        self.assertEqual(result.outcome, INCONCLUSIVE)
        self.assertEqual(result.record_outcomes, {0: INCONCLUSIVE, 2: PASS, 3: PASS})
        self.assertEqual(result.inconclusive_reason, ["missing:record/0/opening"])
        self.assertNotIn("record/0/update", result.requests)

    def test_absent_disposition_withholding_is_inconclusive(self):
        f = fixture()
        snapshot, candidate = f.source["snapshot"], f.source["result"]
        self.assertEqual(bridge.withhold(f, [1]), ["record/1/disposition"])
        result = audit(f.source, f.trust, slots=[0, 1, 2])
        self.assertEqual(result.outcome, INCONCLUSIVE)
        self.assertEqual(result.record_outcomes, {0: PASS, 1: INCONCLUSIVE, 2: PASS})
        self.assertEqual(result.inconclusive_reason, ["missing:record/1/disposition"])
        self.assertEqual((f.source["snapshot"], f.source["result"]), (snapshot, candidate))

    def test_failure_precedes_disjoint_missing_and_keeps_all_findings(self):
        for slots in ([0, 1, 13], [13, 1, 0]):
            with self.subTest(slots=slots):
                f = fixture(active=True)
                bridge.withhold(f, [0, 1])
                result = audit(f.source, f.trust, slots=slots)
                self.assertEqual(result.outcome, FAIL_POLICY)
                self.assertEqual(result.record_outcomes, {0: INCONCLUSIVE, 1: INCONCLUSIVE, 13: FAIL_POLICY})
                self.assertEqual(len(result.inconclusive_reason), 2)
                self.assertEqual(len(result.findings), 3)
                self.assertEqual(result.records_processed, 3)
                self.assertEqual(result.updates_processed, 0)
                self.assertFalse(result.aggregate_verified)

    def test_withholding_ids_fixed_disjoint_and_deterministic(self):
        expected = {4: [6, 7], 309999: [5, 24], 310001: [20, 24], 310020: [24, 29]}
        for seed, slots in expected.items():
            self.assertEqual(bridge.withholding_slots(seed), slots)
            self.assertEqual(validator.withholding_ids(seed, 30), slots)
        for seed in range(310001, 310021):
            slots = bridge.withholding_slots(seed)
            self.assertEqual(len(set(slots)), 2)
            self.assertFalse(set(slots).intersection((13, 15)))
            self.assertEqual(slots, bridge.withholding_slots(seed))

    def test_controller_no_oracle_and_no_replacement(self):
        self.assertEqual(list(inspect.signature(reject_round).parameters), ["outcome"])
        self.assertEqual(list(inspect.signature(next_model).parameters), ["previous", "published", "outcome"])
        w, published = np.array([.2, .3]), np.array([100, -100])
        for outcome in (FAIL_POLICY, "FAIL_ROSTER", "FAIL_RESULT_REPLAY", INCONCLUSIVE):
            self.assertTrue(reject_round(outcome))
            result = next_model(w, published, outcome)
            np.testing.assert_array_equal(result, w)
            self.assertIsNot(result, w)
        for outcome in (PASS, None):
            self.assertFalse(reject_round(outcome))
            np.testing.assert_array_equal(next_model(w, published, outcome), w + published / SCALE)
        checks = validator.check_control_sources(inspect.getsource(bridge), inspect.getsource(inspect.getmodule(next_model)))
        self.assertTrue(all(checks.values()))

    def test_no_oracle_source_guard_rejects_hidden_label_input(self):
        response = inspect.getsource(inspect.getmodule(next_model))
        source = inspect.getsource(bridge).replace("scheduler.choose(seed, r + 1, budget)",
                                                   "scheduler.choose(seed, r + 1, budget, targets)")
        with self.assertRaises(validator.ValidationError):
            validator.check_control_sources(source, response)
        poisoned = response.replace("return previous.copy() if reject_round(outcome)",
                                    "return previous.copy() if True")
        with self.assertRaises(validator.ValidationError):
            validator.check_control_sources(inspect.getsource(bridge), poisoned)

    def test_pure_withholding_uniform_neutral_equality(self):
        kwargs = dict(rounds=12, hidden=2, missing_start=0, missing_end=8)
        uniform = bridge.run_cell("withholding_recovery", "uniform", 4, toy_data(), **kwargs)
        neutral = bridge.run_cell("withholding_recovery", "neutral", 4, toy_data(), **kwargs)
        self.assertGreater(uniform["totals"]["audit_missing_requests"], 0)
        self.assertGreater(uniform["totals"]["rejected_rounds"], 0)
        left, right = strip_timings(uniform), strip_timings(neutral)
        left.pop("method"); right.pop("method")
        self.assertEqual(left, right)

    def test_no_missing_run_cell_matches_v5_neutral_excluding_timings(self):
        options = dict(rounds=14, hidden=2, attack_start=0)
        new = bridge.run_cell("mixed_recovery", "neutral", 4, toy_data(),
                              missing_start=60, missing_end=60, **options)
        old = run_arm("drop_neutral_b3", 4, toy_data(), **options)
        for key in old:
            if key not in ("arm", "round_rows"):
                self.assertEqual(strip_timings(new[key]), strip_timings(old[key]), key)
        for row, previous in zip(new["round_rows"], old["round_rows"]):
            self.assertEqual({key: row[key] for key in previous}, previous)
        self.assertGreater(new["totals"]["prevented_bad_rounds"], 0)
        self.assertEqual(new["totals"]["audit_missing_requests"], 0)

    def test_trace_counters_and_restoration_censoring(self):
        def row(rid, bad, rejected, outcome, missing):
            return dict(round=rid, attack_targets=[13] if bad else [], rejected=rejected,
                        outcome=outcome, missing_requests=missing, local_steps=10)
        trace = [row(38, False, True, INCONCLUSIVE, 1), row(39, True, True, FAIL_POLICY, 1),
                 row(40, True, False, PASS, 0), row(41, False, True, INCONCLUSIVE, 1),
                 row(42, False, False, PASS, 0)]
        expected = dict(applied_violating_rounds=1, prevented_violating_rounds=1,
            compliant_rounds_retained=2, compliant_missing_retained=2, compliant_rounds=3,
            missing_finding_rounds=3, mixed_fail_missing_rounds=1, inconclusive_only_rounds=2,
            longest_retention_streak=2, post_restore_first_apply_delay=1,
            post_restore_apply_censored=False, discarded_steps_fraction=.6, discarded_compliant_steps=20)
        self.assertEqual(bridge.trace_metrics(trace), expected)
        self.assertEqual(validator.bridge_from_trace(trace), expected)
        for shortened in (trace[:4], trace[:3]):
            result = bridge.trace_metrics(shortened)
            self.assertTrue(result["post_restore_apply_censored"])
            self.assertIsNone(result["post_restore_first_apply_delay"])
            self.assertEqual(result, validator.bridge_from_trace(shortened))


class TraceValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cells = {method: bridge.run_cell("mixed_recovery", method, 4, toy_data(),
                      rounds=14, hidden=2, attack_start=0, missing_start=0, missing_end=8)
                     for method in bridge.METHODS}
        cls.options = dict(features=3, hidden=2, rounds=14, attack_start=1,
                           missing_start=1, missing_end=8)

    def validate(self, row):
        return validator.validate_cell(row, [6] * 30, **self.options)

    def test_all_methods_synthetic_trace_and_bytes_validate(self):
        for method, row in self.cells.items():
            with self.subTest(method=method):
                result = self.validate(row)
                self.assertEqual(result["bridge"], row["bridge"])
                self.assertEqual(result["totals"], {k: v for k, v in row["totals"].items()
                                                    if k not in validator.TIMINGS})

    def test_trace_tampering_is_never_ignored(self):
        mutations = {
            "overall_outcome": lambda r: r["round_rows"][0].update(outcome="FAIL_RESULT_REPLAY"),
            "budget": lambda r: r["round_rows"][0]["audit_slots"].pop(),
            "missing_count": lambda r: r["round_rows"][0].update(missing_requests=99),
            "request_bytes": lambda r: r["round_rows"][0].update(request_bytes=0),
            "payload_bytes": lambda r: r["round_rows"][0].update(payload_bytes=0),
            "framing_bytes": lambda r: r["round_rows"][0].update(framing_bytes=0),
            "request_names": lambda r: r["round_rows"][0]["requests"].append("result"),
            "total_counter": lambda r: r["totals"].update(rejected_rounds=999),
            "bridge_counter": lambda r: r["bridge"].update(compliant_rounds_retained=999),
            "censoring": lambda r: r["bridge"].update(post_restore_apply_censored=False),
            "target_ids": lambda r: r.update(withholding_ids=[13, 15]),
            "phase": lambda r: r["round_rows"][-1].update(withholding_slots=r["withholding_ids"]),
            "training_schedule": lambda r: r["round_rows"][0]["chosen"].reverse(),
            "hash_chain": lambda r: r["round_rows"][0].update(previous_model_sha256="0" * 64),
            "partial_trace": lambda r: r["round_rows"].pop(),
            "nonfinite_timing": lambda r: r["totals"].update(audit_cpu_ms=float("nan")),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                row = copy.deepcopy(self.cells["neutral"])
                mutate(row)
                with self.assertRaises(validator.ValidationError):
                    self.validate(row)

    def test_rejected_model_hash_must_be_retained(self):
        row = copy.deepcopy(self.cells["neutral"])
        rejected = next(r for r in row["round_rows"] if r["rejected"])
        rejected["applied_model_sha256"] = "0" * 64
        with self.assertRaisesRegex(validator.ValidationError, "retain hash"):
            self.validate(row)

    def test_per_slot_outcomes_checked_not_only_overall(self):
        row = copy.deepcopy(self.cells["neutral"])
        point = row["round_rows"][0]
        slot = next(iter(point["record_outcomes"]))
        point["record_outcomes"][slot] = "FAIL_ROSTER"
        with self.assertRaisesRegex(validator.ValidationError, "record_outcomes"):
            self.validate(row)

    def test_design_configurable_development_and_frozen_evaluation(self):
        cfg = dict(seeds=1, seed_start=309999, rounds=60, scenarios=list(bridge.SCENARIOS),
                   methods=list(bridge.METHODS), budget=3, attack_rounds=[21, 60],
                   missing_rounds=[21, 40], restoration_round=41)
        self.assertEqual(validator.check_design(cfg, expected_cells=10), ([309999], 10))
        with self.assertRaises(validator.ValidationError):
            validator.check_design(cfg, evaluation=True, expected_cells=10)
        cfg.update(seeds=20, seed_start=310001)
        self.assertEqual(validator.check_design(cfg, evaluation=True), (list(range(310001, 310021)), 200))
        with self.assertRaises(validator.ValidationError):
            validator.check_design(cfg, evaluation=True, expected_cells=10)
        cfg["missing_rounds"] = [20, 40]
        with self.assertRaises(validator.ValidationError):
            validator.check_design(cfg, evaluation=True)

    def test_strict_json_rejects_nan_and_duplicate_keys(self):
        for text in ('{"x":NaN}', '{"x":Infinity}', '{"x":1,"x":2}'):
            with self.assertRaises(validator.ValidationError):
                validator.strict_json(text, "synthetic")

    def test_failed_marker_and_missing_artifacts_fail_without_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "FAILED.json").write_text('{"error":"synthetic failure"}', encoding="utf8")
            result = validator.validate_root(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("FAILED.json", result["errors"][0])
            self.assertFalse((root / "validation.json").exists())
        with tempfile.TemporaryDirectory() as temp:
            result = validator.validate_root(temp)
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(result["errors"])
            self.assertFalse((Path(temp) / "validation.json").exists())

    def test_only_cli_main_writes_validation_and_failure_exit_is_nonzero(self):
        with tempfile.TemporaryDirectory() as temp:
            with contextlib.redirect_stdout(io.StringIO()):
                code = validator.main(["--root", temp, "--expected-cells", "10"])
            self.assertEqual(code, 1)
            report = json.loads((Path(temp) / "validation.json").read_text(encoding="utf8"))
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(sorted(p.name for p in Path(temp).iterdir()), ["validation.json"])

    def test_bootstrap_single_seed_schema_and_nonfinite_rejection(self):
        self.assertEqual(validator.bootstrap([7]), {"n": 1, "mean": 7., "ci": None})
        self.assertEqual(validator.bootstrap([]), {"n": 0, "mean": None, "ci": None})
        with self.assertRaises(validator.ValidationError):
            validator.bootstrap([0, float("nan")])

    def test_bootstrap_primary_numpy_reference_without_v5_helper(self):
        values = np.array([-8., -3., 0., 1., 7., 12.])
        level = 1 - .05 / 3
        rng = np.random.default_rng(776655)
        # Scalar draws form the same RNG stream but use a distinct implementation.
        means = np.array([np.mean(values[rng.integers(0, len(values), len(values))])
                          for _ in range(20000)])
        expected = np.percentile(means, [(1 - level) * 50, (1 + level) * 50])
        with patch("experiments.pba_v3.v5_common.bootstrap", side_effect=AssertionError("v5 helper forbidden")):
            result = validator.bootstrap(values, confidence=level)
        np.testing.assert_allclose(result["ci"], expected, rtol=1e-12, atol=1e-12)
        self.assertEqual(result["mean"], 1.5)
        self.assertEqual(result["resamples"], 20000)
        self.assertEqual(result["confidence"], level)

    def test_all_summary_means_paired_and_primary_family(self):
        # Synthetic summaries only: no model/evaluation jobs and no real data.
        rows = []
        for seed in range(310001, 310021):
            for si, scenario in enumerate(bridge.SCENARIOS):
                for mi, method in enumerate(bridge.METHODS):
                    row = dict(seed=seed, scenario=scenario, method=method,
                               initial_model_sha256=str(seed), selection_schedule_sha256=str(seed))
                    for section, keys in validator.MEAN_KEYS.items():
                        row[section] = {key: (seed % 7) * (mi + 1) + si for key in keys}
                    row["bridge"].update(post_restore_apply_censored=seed % 4 == 0,
                                         post_restore_first_apply_delay=None if seed % 4 == 0 else seed % 3)
                    rows.append(row)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "config.json").write_text(json.dumps(dict(seed_start=310001, seeds=20)), encoding="utf8")
            (root / "COMPLETE.json").write_text(json.dumps(dict(completed=200, expected=200)), encoding="utf8")
            (root / "rows.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf8")
            expected = bridge.analyze(root)
        with patch("experiments.pba_v3.v5_common.bootstrap", side_effect=AssertionError("v5 helper forbidden")):
            actual = validator.recompute_summary(rows)
        validator.compare(actual, expected, "summary regression")
        self.assertEqual(actual["primary_family_size"], 3)
        self.assertEqual(actual["primary_confidence"], 1 - .05 / 3)
        self.assertEqual(len(actual["means"]), 10)
        self.assertEqual(len(actual["paired"]), 6)
        for contrast in validator.PRIMARY:
            key = "mixed_recovery/" + "-".join(contrast)
            self.assertEqual(actual["paired"][key]["primary"]["resamples"], 20000)
        broken = copy.deepcopy(actual)
        broken["paired"]["mixed_recovery/neutral-adaptive"]["primary"]["ci"][0] += 1
        with self.assertRaises(validator.ValidationError):
            validator.compare(broken, actual, "summary tampering")


if __name__ == "__main__":
    unittest.main()
