# E11 — Common byte budget rerun (response to R3-7)

## Question

R3-7 notes that the four schedules inspect equal numbers of records but incur
different communication costs, and asks for the principal comparison to be
repeated under a common byte budget.

## Design

- Harness: the 60-round scheduling experiment of `experiments/pba_v3/v5_scheduler.py`
  (30 clients, dimension 256, seven scenarios, four schedules), unchanged except
  for the budget rule.
- Budget: a per-round byte ceiling calibrated **per seed** on an honest fixture.
  The ceiling is the cost of a three-record all-PASS round,
  `fixed + 3 x max_client_cost`; measured 12,327 bytes (fixed 1,104 bytes,
  per-record marginal 3,729–3,741 bytes).
- Spending rule: records are selected in each schedule's own priority order
  until the next record would exceed the ceiling. **Unspent bytes are carried
  into the next round** (clamped to ±1 ceiling), so the comparison is on a
  common cumulative byte budget over 60 rounds, not a per-round cap that a
  cheap response can evade. A residual rule spends any remaining bytes on the
  cheapest uninspected record; it applies identically to every arm.
- Seeds: 20 matched seeds (240001–240020), 560 arm-scenario cells,
  115,216 semantic checks.

## Result

Arm-level mean traffic spans 0.729–0.740 MB and differs from the 0.73962 MB target
by at most 1.4%; individual runs span 0.727–0.740 MB (maximum deviation 1.7%).
Within that common budget the arms inspect different numbers of records, because
response size depends on the outcome:

| Scenario | Arm | TDR | 95% CI | MB/run | records/round |
|---|---|---|---|---|---|
| mixed | uniform | 0.1692 | [0.144, 0.195] | 0.737 | 3.17 |
| mixed | adaptive | 0.9106 | [0.851, 0.959] | 0.729 | 4.42 |
| mixed | neutral | **0.9356** | [0.896, 0.967] | 0.732 | 3.86 |
| mixed | separated | 0.9106 | [0.851, 0.959] | 0.731 | 4.20 |
| moving_mixed | uniform | 0.2115 | [0.193, 0.230] | 0.737 | 3.19 |
| moving_mixed | neutral | 0.1942 | [0.171, 0.215] | 0.737 | 3.13 |
| recovery | neutral | 0.9356 | [0.896, 0.967] | 0.733 | 3.82 |
| integrity_only | neutral | 0.9125 | [0.853, 0.961] | 0.733 | 3.77 |

Paired differences in the mixed scenario (95% CI):

- neutral − uniform: TDR **+0.7663** [0.723, 0.804]; bytes −4,234 B (−0.57%);
  +40.85 inspected records over 60 rounds (+0.68 per round).
- neutral − separated: +0.0250 [0.000, 0.073]; bytes +1,184 B; −20.6 records.
- neutral − adaptive: +0.0250 [0.000, 0.073]; bytes +3,302 B; −34.1 records.

Under moving targets the ordering reverses as before: neutral − uniform
−0.0173 [−0.045, 0.010] in moving-mixed, while uniform measures 0.2115 versus
0.1942. The byte-controlled rerun therefore reproduces both the stationary
advantage and the moving-target boundary.

## Why the bytes differed at equal record counts

Per-record evidence is fixed-size: single-record marginal cost spans only
3,729–3,741 bytes across all 30 clients (12 bytes, 0.3%). The arm-level gap in
the record-budget experiments is a **response-mix** effect, not an unequal
amount of inspected data:

| Round type (3 records) | Bytes |
|---|---|
| all PASS | 12,285 |
| one FAIL_POLICY | 10,136 |
| two FAIL_POLICY | 7,987 |
| two INCONCLUSIVE_EVIDENCE | 8,057 |

FAIL and INCONCLUSIVE responses omit the aggregate replay and the opening
payload, so an arm that finds problems spends *fewer* bytes per round. At a
common byte budget that saving is carried forward and converted into additional
inspections: neutral inspects 3.86 records per round versus 3.17 for uniform,
while spending 0.6% fewer bytes. This is the correct reading of the byte
asymmetry the reviewer noticed, and it favours, rather than penalises, targeted
auditing.

## Reading

- The principal comparison is already byte-controlled up to response mix; a
  common cumulative byte budget does not change the ranking.
- The byte asymmetry in the paper (neutral below uniform) is attributable to
  FAIL/INCONCLUSIVE responses being smaller, not to neutral inspecting less
  data. Under an equal byte budget neutral converts the saving into more
  inspected records.
- Limit: the per-record evidence size is constant because the update vector has
  a fixed dimension. A byte budget is therefore a record budget up to a
  response-mix term; with variable-length updates the same controller would
  trade records against size directly.

## Files

- `run_e11.py`, `results/summary.json`, `results/seed_*.json`, `results/manifest.json`.
