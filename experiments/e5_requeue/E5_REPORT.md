# E5 — Evidence-restored bounded re-queue

Status: **complete** — 20 matched seeds (320001–320020), 2 scenarios × 5 arms, 60 rounds, b = 3.
Script: `experiments/e5_requeue/run_e5.py` → `results/summary.json`.

## 1. Mechanism

While evidence is withheld (rounds 21–40), any selected client whose opening is missing produces INCONCLUSIVE and its update is rejected. After restoration (round 41), the requeue arms:

- pull up to 2 still-unverified clients back into the local training set and into the audit slots (controller override on top of the scheduler),
- retry at most twice; a PASS admits the update, a second INCONCLUSIVE censors the client, a FAIL keeps the normal rejection path,
- never admit an update before a PASS.

## 2. Results (mean, 20 seeds)

`mixed_recovery`:

| arm | applied violations | compliant rejected | discarded fraction | F1 | audit MB | re-entry delay (rounds) |
|---|---|---|---|---|---|---|
| neutral | 10.40 | 1.25 | 0.227 | 0.7180 | 2.72 | 0.65 |
| neutral_requeue | 10.65 | 1.25 | 0.223 | 0.7181 | 2.79 | **0.15** |
| separated | 8.75 | 2.60 | 0.277 | 0.7170 | 2.70 | 0.65 |
| separated_requeue | 9.00 | 2.60 | 0.272 | 0.7171 | 2.75 | **0.15** |
| adaptive | 7.50 | 5.60 | 0.347 | 0.7165 | 2.62 | 0.65 |

`withholding_recovery` (no integrity attacks): applied violations 0 in every arm; neutral 3.5 compliant rejections / F1 0.747, separated 7.1 / 0.746, adaptive 13.35 / 0.742; requeue leaves all three unchanged and re-entry delay already 0.

Paired (97.5% CI): requeue − control on `mixed_recovery` → applied violations **+0.25 [+0.10, +0.45]**, discarded fraction **−0.0042 [−0.0075, −0.0017]**, F1 **−0.0002 [−0.0009, +0.0005]**, compliant rejections 0.

## 3. Reading

1. **The only measurable gain is recovery latency**: post-restore re-entry drops from 0.65 to 0.15 rounds (≈ 4× faster), i.e. the update returns in the first or second round instead of waiting for a random selection to revisit the client.
2. **Accuracy does not improve.** F1 is unchanged, compliant rejection is unchanged, and the applied-violation count rises by 0.25 (the requeue changes which clients train, and occasionally re-admits a slot in an attacked round). The honest statement: re-queue is an audit-hygiene mechanism, not an accuracy mechanism.
3. **Cost is small** (+1.6 forced slots per run, +0.06–0.07 MB) and no unverified update is ever admitted, so the safety property is preserved.
4. **Recommendation for the revision**: keep re-queue as an optional recovery policy, report its latency effect, and explicitly say it does not improve F1. Claiming an accuracy gain would be false and a reviewer with the numbers would catch it.
