# v5 decision experiment — frozen design before evaluation

## Material Passport

- Origin Skill: academic-research-suite / experiment-agent
- Origin Mode: run + validate; implementation explicitly authorized by user
- Origin Date: 2026-10-22
- Verification Status: UNVERIFIED until executed and checked
- Version Label: decision_v5_20261022

## Scope and earlier development failure

This study supports a research investment decision, not a ready-to-submit claim.
The original manuscript, frozen release_v4 and historical scripts remain unchanged.
`v5_scheduler_smoke.json` and `run_v5_scheduler.py` are INVALID development artifacts:
the initial separated comparator was uniform in disguise, coverage included clean
rounds, and evaluation seed IDs overlapped development. The 100-seed execution
of that initial runner was stopped before completion; none of its outputs is used.
The corrected runner is `v5_scheduler.py`. No segment redesign is implemented.

## Step 1: scheduler comparison

- Methods: uniform; original adaptive (+1 failure,+.5 missing); availability-neutral
  (+1 failure, no missing increment); simple separated (same integrity risk,
  missing-evidence cooldown 3 rounds, at most one oldest due retry, remaining
  budget for eligible integrity checks, fill remaining slots if budget exceeds pool).
- All arms: K=30, b=3, 60 rounds, actual authenticated record verifier. All b
  records processed, no extra free availability probes. Same per-round exponential
  random priorities; no attack labels passed to scheduler. Scores initialized zero.
- Primary dimension256; d6241 validation uses the first20 evaluation seeds220001..220020,
  same b3. Optional separate b6 sensitivity uses the same100 seeds at d256.
  These are paired sensitivity subsets, not independent replication populations.
- Development seeds210001..210003; evaluation220001..220100. No development seed
  enters headline evaluation. This is an internal frozen plan, not public registration.
- Random per-seed permutation defines two integrity and two disjoint withholding
  targets. Attacks start round9. Scenarios: honest; integrity_only; mixed;
  recovery (withholding ends32, integrity persists); moving_integrity;
  moving_mixed (integrity shifts every4 rounds using predetermined trace, no
  current-selection knowledge); withholding_only. The exact permutation is
  NumPy default_rng(SeedSequence([seed,91002])).permutation(30); order[0:2] are
  integrity targets, order[2:4] withholding, moving targets take consecutive pairs
  from order[0:2]+order[4:] cyclically, advancing two positions every4 attacked rounds.
  Mixed/counterfactual pairs share
  identical integrity traces. Withholding concerns opening availability, not tampering.
- Denominators: round integrity TDR=attacked rounds with >=1 confirmed integrity
  failure / integrity-attacked rounds; record TDR=confirmed targeted records /
  all corrupted records; coverage=selected targeted records / all corrupted records.
  Availability observations have their own denominator and are NOT integrity TDR.
  No-attack rates are null, not zero. Missing findings counted even when overall
  outcome is FAIL. Report first detection with right-censored counts, not only hits.
- Report bytes from actual verifier framing, record attempts, missing requests,
  CPU time (instrumented diagnostic only), recovered-target reinspection and misses.
  Recovery latency is first reinspection minus33, censored after round60 (28 rounds).
  Separated cooldown is soft: if eligible records cannot fill b, other records fill
  the budget. Bytes are actual Reader application framing, not TCP/TLS wire traffic.
  Equal b is not equal traffic or CPU; no equal-byte optimality claim.
- Paired seed percentile bootstrap (20,000 draws). Primary comparisons: neutral
  minus uniform, neutral minus separated on mixed integrity-round TDR. Show95% and
  Bonferroni97.5% intervals for this family of two. Other intervals descriptive.
- Investment threshold chosen before main evaluation: >=5 percentage points TDR
  advantage and primary97.5% lower bound>0 against BOTH comparators. Examine all
  scenarios and costs; fixed-target success alone is not general novelty.

## Step 2: no-free-oracle response

- Existing UNSW-NB15 12000/4000 bounded subset, fixed client partition, original
  NumPy MLP32 and original hyperparameters. No new attack selected from test F1.
- 20 matched seeds300001..300020; 60 rounds; 10 of30 clients per round. Attack:
  same declared-policy-invalid exclusion of clients15,13 during rounds21..60.
- Arms: clean/noaudit, attacked/noaudit, attacked/uniform b3, attacked/neutral b3,
  attacked/separated b3, attacked/full replay b30 reference. All audited arms
  audit EVERY round, including preattack rounds and rounds without targeted clients.
- Decision uses ONLY verifier outcome: reject FAIL or INCONCLUSIVE; retain previous
  model. No replacement aggregate, oracle labels, retry, or free retraining. All
  local training work including discarded rounds counted. No claim PASS spot
  validates global result. Full replay requires all evidence and has measured cost.
- Outcomes: bad rounds applied/prevented, policy-clean rounds rejected, final F1/BA
  and trajectories, skipped optimization steps, actual minibatch rows, discarded
  work, update upload/model broadcast payloads, evidence retrieval including absent
  replies, audit CPU and elapsed training. Network costs are modeled encoded payload
  accounting, not a new deployment/network measurement; timings not performance proof.
- Primary application contrasts neutral vs attacked/noaudit and uniform vs attacked/
  noaudit: paired seed F1 and bad-round reduction. Other comparisons descriptive.
  Fixed split uncertainty is across training seeds, NOT new datasets/sites/partitions.

## Step 3 decision

Only after both evaluations: distinguish (a) usefulness of evidence-driven rejection,
(b) novelty of the neutral rule over simple separation, (c) need for authenticated
coordinate evidence. No positive segment attribution without a client-bound construction
and realistic overhead. A negative scheduler result does not justify automatic
large cryptographic redesign. No manuscript changes or concealment of negative results.
