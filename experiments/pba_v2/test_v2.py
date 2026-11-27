import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pba_v2.codec import canon, digest, leaf, Tree
from pba_v2.repository import build_round, make_fixture, mutate, tamper, signed
from pba_v2.verify import audit, PASS, FAIL_ROSTER, FAIL_POLICY, FAIL_RESULT_REPLAY, INCONCLUSIVE
from pba_v2.run_budget_v3 import update_risk_scores, evaluate_round


class GuardStore(dict):
    """Evidence reader guard used to prove that spot audits are local.

    The verifier is allowed to read the common public objects and explicitly
    selected slots only. Any unselected evidence access raises immediately.
    """
    def __init__(self, source, allowed):
        super().__init__(source)
        self.allowed = set(allowed)
        self.accessed = []

    def get(self, key, default=None):
        self.accessed.append(key)
        if key not in self.allowed:
            raise AssertionError(f"unselected evidence accessed: {key}")
        return super().get(key, default)


class PBA2Tests(unittest.TestCase):
    def setUp(self):
        fixture = make_fixture(clients=10, dimension=8, seed=11)
        self.source = fixture.source
        self.trust = dict(fixture.trust.__dict__)
        self.keys = fixture.keys

    def trust_obj(self):
        return type('T', (), self.trust)()

    def test_full_pass(self):
        r = audit(self.source, self.trust_obj(), full=True)
        self.assertEqual(r.outcome, PASS)
        self.assertTrue(r.aggregate_verified)
        self.assertTrue(r.global_normalization_checked)
        self.assertEqual(r.records_processed, 10)
        self.assertEqual(r.updates_processed, 10)

    def test_spot_is_local_and_not_aggregate(self):
        r = audit(self.source, self.trust_obj(), slots=[0, 3])
        self.assertEqual(r.outcome, PASS)
        self.assertFalse(r.aggregate_verified)
        self.assertLess(r.records_processed, 10)
        self.assertNotIn('result', r.requests)
        self.assertEqual(r.updates_processed, 2)

    def test_guard_store_proves_spot_locality(self):
        allowed = {'bulletin', 'snapshot', 'policy'}
        for slot in (0, 3):
            allowed.update({
                f'record/{slot}/roster', f'record/{slot}/roster_proof',
                f'record/{slot}/state', f'record/{slot}/state_proof',
                f'record/{slot}/receipt', f'record/{slot}/opening',
                f'record/{slot}/update',
            })
        guarded = GuardStore(self.source, allowed)
        r = audit(guarded, self.trust_obj(), slots=[0, 3])
        self.assertEqual(r.outcome, PASS)
        self.assertEqual(set(r.requests), set(guarded.accessed))
        self.assertFalse(any('/1/' in x or '/2/' in x or '/4/' in x for x in guarded.accessed))
        self.assertNotIn('result', guarded.accessed)

    def test_forged_result_requires_full_replay(self):
        x = mutate(self.source, 'forged_result')
        self.assertEqual(audit(x, self.trust_obj(), slots=[0]).outcome, PASS)
        self.assertEqual(audit(x, self.trust_obj(), full=True).outcome, FAIL_RESULT_REPLAY)

    def test_missing_opening_is_inconclusive(self):
        x = mutate(self.source, 'missing_evidence')
        self.assertEqual(audit(x, self.trust_obj(), slots=[0]).outcome, INCONCLUSIVE)
        self.assertEqual(audit(x, self.trust_obj(), full=True).outcome, INCONCLUSIVE)

    def test_signed_false_count_is_declaration_boundary(self):
        x, t = build_round(clients=10, dimension=8, seed=11, counts=[999] + [20]*9)
        tb = type('T', (), t)()
        self.assertEqual(audit(x, tb, slots=[0]).outcome, PASS)
        self.assertEqual(audit(x, tb, full=True).outcome, PASS)

    def test_policy_blind_does_not_accept_policy_inconsistency_as_failure(self):
        x, t = build_round(clients=10, dimension=8, seed=11, policy_override_slot=0)
        tb = type('T', (), t)()
        self.assertEqual(audit(x, tb, slots=[0], bound=True).outcome, FAIL_POLICY)
        self.assertEqual(audit(x, tb, slots=[0], bound=False).outcome, PASS)

    def test_untrusted_evidence_cannot_replace_trust(self):
        bad = dict(self.trust)
        bad['bulletin_pin'] = '00' * 32
        r = audit(dict(self.source), type('T', (), bad)(), slots=[0])
        self.assertEqual(r.outcome, FAIL_ROSTER)

    def test_snapshot_pin_detects_rebinding(self):
        """A server re-signing a replacement snapshot cannot rewrite history.

        The original signed snapshot digest is retained as the auditor's
        stable pin. The repository is then given a different, validly signed
        snapshot. Verification must reject the rebinding before replay.
        """
        original_pin = self.trust["snapshot_pin"]
        replacement = json.loads(self.source["snapshot"])
        replacement["body"]["denominator"] += 1
        signed(self.source, "snapshot", self.keys.server, "PBA2/server",
               replacement["body"])
        pinned = dict(self.trust)
        pinned["snapshot_pin"] = original_pin
        r = audit(self.source, type("T", (), pinned)(), full=True)
        self.assertEqual(r.outcome, FAIL_ROSTER)
        self.assertTrue(any("snapshot pin" in item["reason"] for item in r.findings))

    def test_actual_read_cost_differs(self):
        spot = audit(self.source, self.trust_obj(), slots=[0])
        full = audit(self.source, self.trust_obj(), full=True)
        self.assertLess(spot.total_network_bytes, full.total_network_bytes)
        self.assertEqual(spot.updates_processed, 1)
        self.assertEqual(full.updates_processed, 10)

    def test_absent_and_timeout_are_authenticated_exclusions(self):
        f = make_fixture(clients=4, dimension=8, seed=17, absent_slots={2, 3})
        r = audit(f.source, f.trust, full=True)
        self.assertEqual(r.outcome, PASS)
        self.assertTrue(r.aggregate_verified)
        self.assertEqual(r.records_processed, 4)
        self.assertEqual(r.updates_processed, 2)

        timeout = make_fixture(clients=4, dimension=8, seed=17, absent_slots={2, 3})
        timeout = tamper(timeout, 'timeout_disposition', slots=(2,))
        r2 = audit(timeout.source, timeout.trust, full=True)
        self.assertEqual(r2.outcome, PASS)
        self.assertTrue(r2.aggregate_verified)

    def test_independent_roster_and_state_roots(self):
        f = make_fixture(clients=4, dimension=8, seed=19, absent_slots={2, 3})
        bulletin = json.loads(f.source['bulletin'])
        snapshot = json.loads(f.source['snapshot'])
        self.assertNotEqual(bulletin['body']['roster_root'], snapshot['body']['state_root'])
        self.assertEqual(bulletin['body']['K'], 4)
        self.assertEqual(snapshot['body']['K'], 4)

    def test_full_audit_reads_only_accepted_updates(self):
        f = make_fixture(clients=4, dimension=8, seed=23, absent_slots={2, 3})
        r = audit(f.source, f.trust, full=True)
        self.assertEqual(r.outcome, PASS)
        self.assertEqual(r.records_processed, 4)
        self.assertEqual(r.updates_processed, 2)
        self.assertEqual(sum('/update' in x for x in r.requests), 2)
        self.assertEqual(sum('/disposition' in x for x in r.requests), 2)

    def test_adaptive_feedback_uses_only_verifier_outcomes(self):
        """The scheduler feedback must not depend on hidden attack labels."""
        f = make_fixture(clients=4, dimension=8, seed=29)
        r = audit(f.source, f.trust, slots=[0, 2])
        left = [0.0] * 4
        right = [0.0] * 4
        update_risk_scores(left, r, [0, 2])
        update_risk_scores(right, r, [0, 2])
        self.assertEqual(left, right)
        # Evaluation labels may use a trace, but they are not part of feedback.
        e = {"ids": {0}, "withhold": False}
        scored = evaluate_round(e, r, "spot", [0, 2])
        self.assertFalse(scored["record_detected"])

    def test_latency_is_censored_when_no_attack_is_detected(self):
        f = make_fixture(clients=4, dimension=8, seed=31)
        r = audit(f.source, f.trust, slots=[0])
        scored = evaluate_round({"ids": {3}, "withhold": False}, r, "spot", [0])
        self.assertFalse(scored["covered"])
        self.assertFalse(scored["record_detected"])


if __name__ == '__main__':
    unittest.main()
