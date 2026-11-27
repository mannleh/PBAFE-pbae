# E6 — Edge-side audit overhead (single-core profile, no energy meter)

Status: **complete, downgraded as agreed** (no Raspberry-Pi-class board, no power meter → energy is **not** measured).
Script: `experiments/e6_overhead/run_e6.py` → `E6_results.json`.
Conditions: verifier pinned to one logical core (psutil affinity [0]), 30 rounds per configuration, dimension 256, 30 clients, 2 tampered records. Latency/loss are **application-layer emulation** (RTT 20/100 ms, loss 1%/5%, RTO 200 ms), reported separately from measured local compute — never merged into one number.

## 1. Measured local compute and footprint (single core)

| budget | compute ms | wall ms (p95) | bytes/round | requests/round | peak RSS MB |
|---|---|---|---|---|---|
| 3 (sampled) | 22.4–25.5 | 32.1–40.5 (59.8–78.0) | 10,427 | 22.3 | 51.7–57.8 |
| 30 (full) | 203.1–212.5 | 296.2–328.1 (434.8–530.6) | 108,853 | 209.0 | 61.4–63.9 |

## 2. Emulated network time (per round)

| budget | 20 ms / 1% | 20 ms / 5% | 100 ms / 1% | 100 ms / 5% |
|---|---|---|---|---|
| 3 | 492 ms | 659 ms | 2,273 ms | 2,440 ms |
| 30 | 4,553 ms | 6,180 ms | 21,273 ms | 22,900 ms |

## 3. Reading

1. **Sampled audit is edge-viable, full audit is not.** b = 3 costs ~24 ms of CPU, ~10.4 KB and ~52–58 MB peak RSS; at 100 ms RTT it costs ~2.3–2.5 s per round. Full-scope verification is 10× the bytes and ~9× the CPU but **~21 s per round** at 100 ms RTT — it cannot run every round on a constrained link, which is exactly why the paper treats full scope as a periodic anchor rather than the default.
2. **Bandwidth, not CPU, is the binding constraint.** The compute difference between b = 3 and b = 30 is 0.2 s; the network difference is 4–19 s. This supports the paper's budget framing: the scarce resource is audit traffic and latency, not local arithmetic.
3. **Memory is modest but not free.** 52 MB for a Python verifier with per-record Merkle proofs is acceptable on a 1 GB edge node, but it is an order of magnitude above the 6,241-parameter model itself — worth stating honestly.
4. **Limits.** No hardware power measurement; no kernel `tc netem` (Windows host); RSS is OS-level, CPU pinned but the host is a desktop-class core, not a Pi-class ARM core. The letter must say "single-core confined profile with emulated RTT/loss; energy and Pi-class ARM throughput not measured", not "edge deployment validated".
