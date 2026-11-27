"""No-oracle controller, fixture parity, and matched training regression tests."""
import unittest
from unittest.mock import patch

import numpy as np

from experiments.pba_v3.codec import SCALE, decode_vector
from experiments.pba_v3.repository import Keys
from experiments.pba_v3.verify import FAIL_POLICY, INCONCLUSIVE, PASS, audit
from experiments.pba_v3.v5_response import (
    build_training_fixture, next_model, published_aggregate, reject_round, run_arm,
)


def toy_data():
    rng = np.random.default_rng(144)
    X = rng.normal(size=(180, 3))
    y = np.tile([0, 1], 90)
    return ({"X_train": X, "y_train": y, "X_test": X[:40], "y_test": y[:40]},
            [list(range(i * 6, (i + 1) * 6)) for i in range(30)])


class ResponseTests(unittest.TestCase):
    def test_controller_rejects_without_truth(self):
        w, delta = np.array([.2, .3]), np.array([100, -100])
        for outcome in (FAIL_POLICY, "FAIL_ROSTER", "FAIL_RESULT_REPLAY", INCONCLUSIVE):
            self.assertTrue(reject_round(outcome))
            np.testing.assert_array_equal(next_model(w, delta, outcome), w)
        for outcome in (PASS, None):
            self.assertFalse(reject_round(outcome))
            np.testing.assert_array_equal(next_model(w, delta, outcome), w + delta / SCALE)

    def test_aggregate_matches_fixture_clean_and_drop(self):
        chosen = [0, 2, 13, 15]
        vectors = [np.array([1, -2, 3]), np.array([-4, 5, 2]),
                   np.array([8, -3, 4]), np.array([-2, 7, 9])]
        counts = [10, 12, 14, 16]
        keys = Keys.generate(range(30))
        for active in (False, True):
            aggregate = published_aggregate(vectors, counts, chosen, active)
            f = build_training_fixture(np.zeros(3), vectors, counts, chosen, 30, 7,
                                       1, keys, active, aggregate)
            np.testing.assert_array_equal(aggregate, decode_vector(f.source["result"], 3))
            result = audit(f.source, f.trust, full=True)
            self.assertEqual(result.outcome, FAIL_POLICY if active else PASS)
            self.assertEqual(result.replay_performed, not active)

    def test_matched_rng_audits_healthy_and_counts_small_batches(self):
        data = toy_data()
        clean = run_arm("clean_noaudit", 4, data, rounds=2, hidden=2)
        uniform = run_arm("drop_uniform_b3", 4, data, rounds=2, hidden=2)
        self.assertEqual(clean["selection_schedule_sha256"], uniform["selection_schedule_sha256"])
        self.assertEqual(clean["initial_model_sha256"], uniform["initial_model_sha256"])
        self.assertEqual(clean["final_model_sha256"], uniform["final_model_sha256"])
        self.assertEqual(uniform["totals"]["audit_calls"], 2)
        self.assertEqual(uniform["totals"]["local_rows_processed"], 2 * 10 * 6)
        self.assertEqual(uniform["totals"]["honest_rounds_rejected"], 0)
        self.assertEqual(uniform["totals"]["audit_missing_requests"], 0)

    def test_healthy_inconclusive_retains_model_and_counts_discard(self):
        real_audit = audit

        def unavailable(source, trust, **kwargs):
            broken = dict(source)
            broken.pop("policy")
            return real_audit(broken, trust, **kwargs)

        with patch("experiments.pba_v3.v5_response.audit", side_effect=unavailable):
            row = run_arm("drop_uniform_b3", 4, toy_data(), rounds=2, hidden=2)
        self.assertEqual(row["initial_model_sha256"], row["final_model_sha256"])
        self.assertEqual(row["totals"]["honest_rounds_rejected"], 2)
        self.assertEqual(row["totals"]["discarded_training_steps"], 20)
        self.assertEqual(row["totals"]["discarded_rows_processed"], 120)
        self.assertEqual(row["totals"]["audit_missing_requests"], 2)

    def test_full_drop_retains_no_honest_replacement(self):
        row = run_arm("drop_full_b30", 8, toy_data(), rounds=2, selected=30, hidden=2,
                      attack_start=0)
        self.assertEqual(row["initial_model_sha256"], row["final_model_sha256"])
        self.assertEqual(row["totals"]["prevented_bad_rounds"], 2)
        self.assertEqual(row["totals"]["attacked_updates_applied"], 0)
        self.assertEqual(row["totals"]["full_audit_calls"], 2)
        self.assertEqual(row["totals"]["actual_replays"], 0)
        self.assertEqual(row["totals"]["response_extra_payload_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
