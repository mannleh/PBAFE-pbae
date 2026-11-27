# E12 — Training-side scale-out: K = 100 / 200 with a ~50k-parameter model

## Question

R3-4 asks for validation on a larger federation; R3-9 asks for scalability
beyond K = 30 with a deeper classifier. E2b covered only the audit side.

## Design

- Population: K ∈ {100, 200} clients, Dirichlet α = 0.5 over the same 12,000
  official UNSW-NB15 training rows (client size 1–554 rows; K = 100: 120 rows
  mean, K = 200: 60 rows mean).
- Model: one hidden layer, 256 units, 193 inputs — **49,921 parameters**
  (6,241 in the released K = 30 configuration).
- Protocol held at the paper's proportions: nine clients selected per 30
  (selected = K/3, i.e. 33 and 66), audit budget b = K/10 (10 and 20), b = 3 at
  K = 30 is 10%, so per-round audit coverage and participant share are unchanged.
- Adversary: coalition of 6.7% of clients (7 of 100, 13 of 200 — the same share
  as 2 of 30) chosen by attack-row count, drop-update manipulation, onset at
  round 20. Ten matched seeds (310001–310010) per cell; 60 runs.
- Controller: reject FAIL/INCONCLUSIVE, retain previous model, no replacement.

## Result

| K | Arm | F1 | attacked rounds | applied | discarded steps | audit KB/round | verifier CPU ms/round |
|---|---|---|---|---|---|---|---|
| 100 | no audit | 0.7545 | 37.5 | 37.5 | 0 | — | — |
| 100 | uniform b=10 | 0.7546 | 37.5 | 29.2 | 273.9 | 1,269.7 | 158.4 |
| 100 | neutral b=10 | 0.7536 | 37.5 | **10.1** | 904.2 | 1,035.0 | 109.6 |
| 200 | no audit | 0.7533 | 39.8 | 39.8 | 0 | — | — |
| 200 | uniform b=20 | 0.7538 | 39.8 | 24.6 | 1,003.2 | 2,537.8 | 294.3 |
| 200 | neutral b=20 | 0.7560 | 39.8 | **6.7** | 2,184.6 | 2,143.8 | 237.3 |

Paired differences (10 seeds, 95% percentile CI):

- K = 100: neutral − no audit applied violations **−27.4** [−30.2, −23.6];
  F1 −0.0009 [−0.0031, +0.0012]; uniform − no audit −8.3 [−9.6, −7.0].
- K = 200: neutral − no audit **−33.1** [−35.0, −31.0]; F1 +0.0026
  [+0.0001, +0.0047]; uniform − no audit −15.2 [−17.0, −13.4].
- Discarded steps, neutral − uniform: +630.3 [524.7, 716.1] at K = 100,
  +1,181.4 [1,049.4, 1,300.2] at K = 200.

F1 is flat across K (0.753–0.756, seed SD 0.006–0.007) and the audit arms do
not lose accuracy; the containment gain persists and grows with K (73% and 83%
of attacked rounds prevented), at the cost of proportionally more discarded
work. Audit bytes scale linearly in b and in model dimension: 1.04 MB/round at
b = 10, 2.14 MB/round at b = 20 with 49,921-parameter updates.

## Reading

- The training side scales: a 50k-parameter model federates over 100 and 200
  clients with unchanged accuracy and a stronger containment effect.
- Audit cost scales linearly with the budget and the parameter dimension; this
  is expected and is now measured rather than asserted.
- The comparison is proportion-preserving: selected clients and budget both
  scale with K. A fixed b = 3 at K = 100 would audit 3% of the population and
  is not a meaningful deployment setting; the manuscript states the budget rule.
- Limit: 10 seeds per cell; attack rounds are counted (37.5–39.8 of 40), and the
  attack is a drop coalition, not the two-client case of the K = 30 study.

## Files

- `run_e12.py`, `results/rows.json`, `results/summary.json`, `results/paired.json`, `results/config.json`.
