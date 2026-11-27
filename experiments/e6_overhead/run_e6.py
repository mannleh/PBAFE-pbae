# -*- coding: utf-8 -*-
"""E6 — edge-side audit overhead, constrained single-core profile (R1-3 / R1-10).

Hardware limitation: no Raspberry-Pi-class board and no power meter available, so
energy is NOT measured. The verifier process is pinned to ONE logical core and
its maximum sampled post-audit RSS is sampled; latency/loss are applied as an application-layer
network emulation (RTT 20/100 ms, loss 1%/5%, RTO 200 ms) and reported separately
from measured local compute, never merged into a single "wall time" claim.

Per round: sampled (b = 3) and full (b = 30) verification; 30 rounds; bytes,
requests, measured compute ms, modeled network ms, maximum sampled post-audit RSS.
"""
from __future__ import annotations
import json, os, statistics, sys, time
from pathlib import Path

sys.path.insert(0, r".")
import numpy as np
import psutil
from experiments.pba_v3.repository import Keys, make_fixture, tamper
from experiments.pba_v3.verify import audit

ROUNDS = 30
RTO_MS = 200
CONFIGS = [(b, lat, loss) for b in (3, 30) for lat in (20, 100) for loss in (0.01, 0.05)]


def peak_rss_mb():
    return psutil.Process(os.getpid()).memory_info().rss / 1e6


def run_config(budget, latency_ms, loss, seed=440001):
    keys = Keys.generate(list(range(30)))
    wall, cpu, nbytes, nreq, modeled, peaks = [], [], [], [], [], []
    for rid in range(1, ROUNDS + 1):
        base = make_fixture(round_id=rid, dimension=256, clients=30, seed=seed * 1000 + rid, keys=keys)
        bad = (rid % 7, (rid + 3) % 7)
        f = tamper(base, "declared_count_policy", tuple(sorted(bad)))
        slots = list(range(budget))  # deterministic worst-case slice
        t0 = time.perf_counter(); c0 = time.process_time()
        res = audit(f.source, f.trust, slots=slots, full=(budget == 30))
        wall.append((time.perf_counter() - t0) * 1e3)
        cpu.append((time.process_time() - c0) * 1e3)
        nbytes.append(res.total_network_bytes)
        nreq.append(len(res.requests))
        # Application-layer emulation: one sequential request/response per audited record.
        rng = np.random.default_rng(np.random.SeedSequence([seed, rid, budget]))
        lost = int(rng.binomial(nreq[-1], loss))
        net = nreq[-1] * latency_ms + lost * RTO_MS
        modeled.append(net)
        peaks.append(peak_rss_mb())
    return {
        "budget": budget, "latency_ms": latency_ms, "loss": loss, "rounds": ROUNDS,
        "compute_ms_mean": statistics.mean(cpu), "wall_ms_mean": statistics.mean(wall),
        "wall_ms_p95": float(np.percentile(wall, 95)),
        "modeled_network_ms_mean": statistics.mean(modeled),
        "wall_plus_network_ms_mean": statistics.mean(wall) + statistics.mean(modeled),
        "bytes_per_round_mean": statistics.mean(nbytes),
        "requests_per_round_mean": statistics.mean(nreq),
        "peak_rss_mb_max": max(peaks),
        "peak_rss_mb_end": peaks[-1],
    }


def main():
    out = Path(r".\experiments\e6_overhead")
    out.mkdir(parents=True, exist_ok=True)
    try:
        old = psutil.Process().cpu_affinity()
        psutil.Process().cpu_affinity([0])
        pinned = True
    except Exception as exc:  # affinity unsupported
        old, pinned = None, False
        print("affinity unavailable:", exc)
    print("pinned to one core:", pinned)
    results = []
    for cfg in CONFIGS:
        r = run_config(*cfg)
        r["pinned_single_core"] = pinned
        results.append(r)
        print(json.dumps({k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()}, ensure_ascii=False))
    (out / "E6_results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    if old:
        psutil.Process().cpu_affinity(old)


if __name__ == "__main__":
    main()