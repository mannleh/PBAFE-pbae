# E13 — Feasibility envelope under edge-network conditions (R3-9)

## Inputs

Measured local cost (no model in this column):

| Source | K | dimension | budget | CPU ms/round | bytes/round | requests |
|---|---|---|---|---|---|---|
| E2b | 30/100/200 | 256 | 3 | 6.2 / 12.5 / 9.4 | 8.0 / 8.8 / 9.2 KB | 20 |
| E2b | 30/100/200 | 256 | full | 93.8 / 287.5 / 493.8 | 108.9 / 397.5 / 826.3 KB | 209 / 699 / 1,399 |
| E2c | 30 | 6,241 / 49,921 / 99,841 | 3 | 78 / 365 / 703 | 156 KB / 1.2 MB / 2.4 MB | 24 |
| E2c | 100 | 6,241 / 49,921 / 99,841 | 3 | 57 / 333 / 490 | 157 KB / 1.2 MB / 2.4 MB | 24 |
| E2c | 100 | 6,241 / 49,921 / 99,841 | 10 | 167 / 1,078 / 1,083 | 0.52 / 4.0 / 8.0 MB | 73 |

Network term is analytic: one sequential request/response per request,
`RTT` each way counted once per request, plus one 200 ms RTO per lost request.
No kernel netem, no on-device run.

A compute interpolation `cpu = 136.0 + 1,222.4 (b d / 10^6) + 17.8 (K/100)` fits
the measured anchors with leave-one-out error 4.1% mean / 27.2% max; it is used
only between anchors, never to claim beyond them.

## Envelope (1% loss)

Largest RTT that still fits the round period:

| K | dimension | budget | 1 s round | 5 s round |
|---|---|---|---|---|
| 30 | 6,241 | 3 | 20 ms | 200 ms |
| 30 | 49,921 | 3 | 20 ms | 100 ms |
| 30 | 99,841 | 3 | 10 ms | 100 ms |
| 100 | 6,241 | 3 | 20 ms | 200 ms |
| 100 | 49,921 | 3 | 20 ms | 100 ms |
| 100 | 49,921 | 10 | 0 ms | 50 ms |
| 100 | 99,841 | 3 | 10 ms | 100 ms |
| 100 | 99,841 | 10 | 0 ms | 50 ms |
| 30 | 256 | 30 (full) | 1 ms | 20 ms |
| 200 | 256 | 200 (full) | 0 ms | 1 ms |

Representative point (K = 100, d = 49,921, b = 3): 333 ms compute + 24 requests
→ 0.86 s at 20 ms/1%, 2.74 s at 100 ms/1%, 0.33 s with no network delay.
At b = 10 the same configuration is 1.08 s compute and 2.55 s at 20 ms/1%.
Full-scope replay at K = 200 is 28.8 s at 20 ms/1%: it is a periodic anchor, not
a per-round default.

## Reading

- The sampled b = 3 budget is feasible for a 1 s round only on low-latency links
  (≤20 ms at 50k parameters, ≤10 ms at 100k); on a 5 s round it tolerates 100 ms
  RTT up to 100k parameters.
- Budget and dimension, not client count, dominate: K = 30 → 200 changes b = 3
  cost by at most 6.3 ms at d = 256.
- Full-scope verification is never a per-round default at these round periods,
  which is the quantitative form of the paper's "periodic anchor" design.
- Energy is not measured. These are protocol-cost feasibility bounds under
  stated network parameters, not an on-device deployment trial.

## Files

- `run_e13.py`, `envelope.csv` (504 rows), `summary.json`.
