import unittest
from experiments.pba_v3.v5_common import Scheduler, METHODS, bootstrap
from experiments.pba_v3.v5_scheduler import placement, run_seed
from experiments.pba_v3.verify import PASS, INCONCLUSIVE, FAIL_POLICY


class SchedulerTests(unittest.TestCase):
    def test_equal_weights_match_uniform(self):
        for rid in range(1,30):
            selected=[Scheduler(m).choose(13,rid,3) for m in METHODS]
            self.assertTrue(all(x==selected[0] for x in selected))

    def test_neutral_missing_does_not_raise_integrity_risk(self):
        n,a=Scheduler("neutral"),Scheduler("adaptive")
        for sch in (n,a):
            sch.choose(1,9,3)
            sch.observe({2:INCONCLUSIVE,0:FAIL_POLICY})
        self.assertEqual(n.risk[2],0)
        self.assertEqual(a.risk[2],.5)
        self.assertEqual(n.risk[0],1)

    def test_separated_retry_and_recovery(self):
        s=Scheduler("separated")
        s.choose(1,9,3)
        s.observe({2:INCONCLUSIVE})
        self.assertNotIn(2,s.choose(1,10,3))
        self.assertNotIn(2,s.choose(1,11,3))
        self.assertIn(2,s.choose(1,12,3))
        s.observe({2:PASS})
        self.assertNotIn(2,s.due)

    def test_trace_counterfactual_pairing(self):
        for rid in range(1,61):
            self.assertEqual(placement(11,rid,"mixed")[0],placement(11,rid,"integrity_only")[0])
            self.assertEqual(placement(11,rid,"moving_mixed")[0],placement(11,rid,"moving_integrity")[0])
        self.assertNotEqual(placement(11,9,"moving_mixed")[0],placement(11,13,"moving_mixed")[0])
        self.assertFalse(placement(11,33,"recovery")[1])

    def test_real_verifier_smoke(self):
        result=run_seed(210001,dimension=8,rounds=10)
        self.assertEqual(result["semantic_checks"],7*4*10*3)
        for r in result["rows"]:
            self.assertEqual(r["record_attempts"],30)
            self.assertEqual(r["false_fail_rounds"],0)
            if r["attacked_rounds"]:
                self.assertEqual(r["attacked_rounds"],2)
                self.assertEqual(r["record_tdr"],r["coverage"])
                self.assertTrue(0<=r["integrity_tdr"]<=1)
            else:
                self.assertIsNone(r["integrity_tdr"])

    def test_bootstrap_zero(self):
        self.assertEqual(bootstrap([0]*20)["ci"],[0,0])

if __name__=="__main__":
    unittest.main()
