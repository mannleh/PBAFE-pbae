# E2c — Audit-side dimension scaling (anchors for E13)

## Design

Sampled audit only (no training): model dimension d ∈ {6,241; 49,921; 99,841}
(6.2k, 50k, 100k parameters), K ∈ {30, 100} clients, b = 3 and b = K/10,
3 rounds per cell, single process. Records are dense synthetic updates, i.e.
the worst case for serialized size.

## Result

| K | d | b | CPU ms | bytes/round | requests | maximum sampled post-audit RSS MB |
|---|---|---|---|---|---|---|
| 30 | 6,241 | 3 | 78 | 156 KB | 24 | 52 |
| 30 | 49,921 | 3 | 365 | 1.20 MB | 24 | 65 |
| 30 | 99,841 | 3 | 703 | 2.40 MB | 24 | 82 |
| 100 | 6,241 | 3 | 57 | 157 KB | 24 | 63 |
| 100 | 6,241 | 10 | 167 | 0.52 MB | 73 | 64 |
| 100 | 49,921 | 3 | 333 | 1.20 MB | 24 | 100 |
| 100 | 49,921 | 10 | 1,078 | 4.01 MB | 73 | 100 |
| 100 | 99,841 | 3 | 490 | 2.40 MB | 24 | 156 |
| 100 | 99,841 | 10 | 1,083 | 8.01 MB | 73 | 158 |

## Reading

- Cost is linear in the inspected payload `b × d`: 1.2 MB and ~333–365 ms per
  three-record round at 50k parameters; 2.4 MB and 490–703 ms at 100k.
- Client count contributes little at fixed `b × d`; the roster term is
  logarithmic, and maximum sampled post-audit RSS grows with `K × d` (156 MB at 100 × 100k).
- The b = 10 cells reach 1.1 s locally before any network delay, which fixes the
  envelope boundary used in E13: a 1 s audit round is only feasible for b = 3 on
  low-latency links.
- Dense synthetic records are the worst case; the training fixtures in E12
  serialize sparse fixed-point updates and are roughly 4× smaller per record.

## Files

- `run_e2c.py`, `E2c_results.json`.
