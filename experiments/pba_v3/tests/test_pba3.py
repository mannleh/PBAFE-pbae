"""Regression tests for PBA/3.

Each test pins a semantic decision that the experiments depend on. If one of
these breaks, paper numbers are no longer comparable across releases.
"""
import math
import unittest

from experiments.pba_v3.codec import (contribution, derive_challenge_seed,
                                      segment_sums, seg_bounds, sealed_sample)
from experiments.pba_v3.opponents import OPPONENTS, History
from experiments.pba_v3.run_b_segment import miss_bound
from experiments.pba_v3.segfixture import add_segments, build_segment_fixture
from experiments.pba_v3.verify import (FAIL_RESULT_REPLAY, FAIL_ROSTER, INCONCLUSIVE,
                                       audit, audit_segment)


class TestSealedSampling(unittest.TestCase):
    def test_deterministic_for_same_inputs(self):
        s = derive_challenge_seed("ab" * 32, 7, b"beacon")
        self.assertEqual(sealed_sample(s, [1.0] * 30, 3), sealed_sample(s, [1.0] * 30, 3))

    def test_beacon_changes_the_set(self):
        a = derive_challenge_seed("ab" * 32, 7, b"b1")
        b = derive_challenge_seed("ab" * 32, 7, b"b2")
        self.assertNotEqual(sealed_sample(a, [1.0] * 30, 3), sealed_sample(b, [1.0] * 30, 3))

    def test_round_changes_the_set(self):
        a = derive_challenge_seed("ab" * 32, 7, b"b")
        b = derive_challenge_seed("ab" * 32, 8, b"b")
        self.assertNotEqual(sealed_sample(a, [1.0] * 30, 3), sealed_sample(b, [1.0] * 30, 3))

    def test_budget_bounds(self):
        s = derive_challenge_seed("ab" * 32, 1, b"b")
        self.assertEqual(sealed_sample(s, [1.0] * 10, 0), [])
        self.assertEqual(len(set(sealed_sample(s, [1.0] * 10, 10))), 10)
        with self.assertRaises(ValueError):
            sealed_sample(s, [1.0] * 10, 11)

    def test_negative_weight_rejected(self):
        s = derive_challenge_seed("ab" * 32, 1, b"b")
        with self.assertRaises(ValueError):
            sealed_sample(s, [1.0, -1.0], 1)

    def test_sampling_is_without_replacement(self):
        s = derive_challenge_seed("ab" * 32, 1, b"b")
        picks = sealed_sample(s, [1.0] * 30, 12)
        self.assertEqual(len(picks), len(set(picks)))


class TestSegments(unittest.TestCase):
    def test_partition_covers_dimension(self):
        for dim, seg in [(64, 4), (10, 3), (6241, 16)]:
            bounds = seg_bounds(dim, seg)
            self.assertEqual(bounds[0][0], 0)
            self.assertEqual(bounds[-1][1], dim)
            self.assertTrue(all(bounds[i][1] == bounds[i + 1][0] for i in range(len(bounds) - 1)))
            self.assertEqual(sum(hi - lo for lo, hi in bounds), dim)

    def test_contribution_scales(self):
        self.assertEqual(contribution([3, -4, 5], 2), [6, -8, 10])

    def test_honest_segment_audit_passes(self):
        f = build_segment_fixture(dimension=64, clients=10, segments=4, seed=3)
        s = derive_challenge_seed(f.trust.bulletin_pin, 1, b"b")
        self.assertEqual(audit_segment(f.source, f.trust, s, 4).outcome, "PASS")

    def test_every_corrupted_segment_is_caught_when_sampled(self):
        f = build_segment_fixture(dimension=64, clients=10, segments=4, seed=3)
        s = derive_challenge_seed(f.trust.bulletin_pin, 1, b"b")
        for seg in range(4):
            g = add_segments(f, 4, tamper_segments={seg})
            self.assertEqual(audit_segment(g.source, g.trust, s, 4).outcome, FAIL_RESULT_REPLAY)

    def test_multiple_corruptions_persist(self):
        """Repeated single-segment tampering must not silently restore earlier
        segments; this was a real defect in the first implementation."""
        f = build_segment_fixture(dimension=64, clients=10, segments=4, seed=3)
        g = add_segments(f, 4, tamper_segments={0, 1, 2, 3})
        sums = [g.obj(f"segment/{s}") for s in range(4)]
        contributions = []
        accepted = [i for i in range(g.k) if g.obj(f"record/{i}/state")["status"] == "ACCEPTED"]
        contribs = [[g.obj(f"record/{i}/contribution/{s}") for s in range(4)] for i in accepted]
        honest = segment_sums(contribs, 4)
        self.assertNotEqual(sums, honest)

    def test_missing_segment_commitment_is_inconclusive(self):
        f = build_segment_fixture(dimension=64, clients=10, segments=4, seed=3)
        s = derive_challenge_seed(f.trust.bulletin_pin, 1, b"b")
        g = f.clone()
        for seg in range(4):
            g.source.pop(f"segment/{seg}", None)
        g.source.pop("record/0/contribution/0", None)
        r = audit_segment(g.source, g.trust, s, 4)
        self.assertIn(r.outcome, (INCONCLUSIVE, FAIL_ROSTER))

    def test_miss_bound_matches_hypergeometric(self):
        self.assertAlmostEqual(miss_bound(8, 1, 1), 7 / 8)
        self.assertAlmostEqual(miss_bound(8, 1, 4), math.comb(7, 4) / math.comb(8, 4))
        self.assertEqual(miss_bound(8, 8, 4), 0.0)
        self.assertEqual(miss_bound(8, 0, 4), 1.0)


class TestOpponents(unittest.TestCase):
    def test_placement_never_uses_challenge_sets(self):
        """The placement signature has no challenge argument, so a placement
        cannot depend on the current round's sample."""
        import inspect
        for name, cls in OPPONENTS.items():
            params = list(inspect.signature(cls.place).parameters)
            self.assertNotIn("slots", params, name)
            self.assertNotIn("challenge", params, name)

    def test_copycat_migrates_after_failure(self):
        opp = OPPONENTS["copycat"]()
        hist = History()
        rng = __import__("numpy").random.default_rng(1)
        first = opp.place(8, 30, rng, hist, "persistent")
        opp.failed_once = True
        hist.add(8, tuple(first), "PASS")
        second = opp.place(9, 30, rng, hist, "persistent")
        self.assertNotEqual(first, second)

    def test_withhold_responds_by_dropping_openings(self):
        opp = OPPONENTS["withhold"]()
        failures, withheld = opp.respond({0, 1}, (0, 5), None)
        self.assertFalse(failures)
        self.assertEqual(withheld, {0, 1})


class TestAuditSemantics(unittest.TestCase):
    """Availability must never be scored as an integrity detection."""

    def test_inconclusive_is_not_a_failure(self):
        from experiments.pba_v3.repository import make_fixture
        f = make_fixture(dimension=32, clients=8, seed=5)
        f.source.pop("record/0/opening", None)
        r = audit(f.source, f.trust, slots=[0])
        self.assertEqual(r.outcome, INCONCLUSIVE)
        self.assertEqual(r.aggregate_verified, False)

    def test_policy_tamper_is_detected(self):
        from experiments.pba_v3.repository import make_fixture, tamper
        f = make_fixture(dimension=32, clients=8, seed=5)
        g = tamper(f, "declared_count_policy", (0,))
        r = audit(g.source, g.trust, slots=[0])
        self.assertEqual(r.outcome, "FAIL_POLICY")


if __name__ == "__main__":
    unittest.main()
