# -*- coding: utf-8 -*-
"""E3 — adjudicated reactive opponent (R1-3 / R1-10).

Threat model: the adversary observes which slots were audited (audit requests are
public) and, with probability eps, RELOCATES its two tampered clients to the
complement of the last audited set; independently, clients that have been
sampled most often begin WITHHOLDING their openings. Withholding is therefore
frequency-triggered: any scheduler that keeps returning to the same slot loses
evidence exactly there.

Four schedulers (uniform / adaptive / neutral / separated) run against
eps in {0.0 (fixed trajectory), 0.3, 0.7, 1.0}; 100 matched seeds.
Reported: TDR, degradation relative to the fixed trajectory, audit bytes, and
the fraction of rounds whose evidence was withheld.
"""
from __future__ import annotations
import argparse, os, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

for _n in ("OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "OMP_NUM_THREADS"):
    os.environ[_n] = "1"
sys.path.insert(0, r".")
import numpy as np
from experiments.pba_v3.repository import Keys, make_fixture, tamper
from experiments.pba_v3.verify import audit, PASS, INCONCLUSIVE, FAIL_POLICY
from experiments.pba_v3.v5_common import Scheduler, bootstrap, file_hash, write_json
from experiments.pba_v3.v5_scheduler import summarize_rounds

METHODS = ("uniform", "adaptive", "neutral", "separated")
EPS = (0.0, 0.3, 0.7, 1.0)
N = 30


class ReactiveOpponent:
    def __init__(self, seed, eps):
        self.eps = eps
        self.order = np.random.default_rng(np.random.SeedSequence([seed, 91002])).permutation(N).tolist()
        self.integrity = set(self.order[:2])
        self.withhold = set(self.order[2:4])
        self.counts = np.zeros(N)
        self.sampled = np.zeros(N, dtype=bool)

    def next_round(self, rid, prev_slots):
        if self.eps == 0.0:
            return self.integrity, self.withhold
        rng = np.random.default_rng(np.random.SeedSequence([int(self.eps * 1000), rid, 91003]))
        if rid > 1 and rng.random() < self.eps:
            pool = [c for c in range(N) if c not in prev_slots]
            self.integrity = set(map(int, rng.choice(pool, 2, replace=False)))
        # frequency-triggered withholding: most-sampled clients hide their opening
        cand = [c for c in range(N) if c not in self.integrity]
        cand.sort(key=lambda c: (-self.counts[c], c))
        top = [c for c in cand if self.counts[c] > 0][:2]
        if len(top) < 2:
            top += [c for c in self.order[2:4] if c not in self.integrity and c not in top]
        self.withhold = set(map(int, top[:2]))
        return self.integrity, self.withhold

    def observe_slots(self, slots):
        for c in slots:
            self.counts[c] += 1
            self.sampled[c] = True


def derive(base, bad, missing):
    f = tamper(base, "declared_count_policy", tuple(sorted(bad))) if bad else base.clone()
    for c in missing:
        f.source.pop(f"record/{c}/opening", None)
    return f


def run_seed(seed, eps, rounds=60, budget=3, dimension=256):
    keys = Keys.generate(list(range(N)))
    schedulers = {m: Scheduler(m) for m in METHODS}
    opps = {m: ReactiveOpponent(seed, eps) for m in METHODS}
    traces = {m: [] for m in METHODS}
    prev = {m: [] for m in METHODS}
    verified = 0
    for rid in range(1, rounds + 1):
        base = make_fixture(round_id=rid, dimension=dimension, clients=N, seed=seed * 1000 + rid, keys=keys)
        cache = {}
        for m in METHODS:
            bad, missing = opps[m].next_round(rid, prev[m])
            if rid < 9:
                bad, missing = set(), set()
            key = (tuple(sorted(bad)), tuple(sorted(missing)))
            if key not in cache:
                cache[key] = derive(base, bad, missing)
            f = cache[key]
            slots = schedulers[m].choose(seed, rid, budget)
            res = audit(f.source, f.trust, slots=slots)
            expected = {c: FAIL_POLICY if c in bad else INCONCLUSIVE if c in missing else PASS for c in slots}
            assert res.record_outcomes == expected, (m, rid, expected, res.record_outcomes)
            verified += len(slots)
            schedulers[m].observe(res.record_outcomes)
            opps[m].observe_slots(slots)
            prev[m] = slots
            traces[m].append({"round": rid, "slots": slots,
                              "integrity_targets": sorted(bad), "withholding_targets": sorted(missing),
                              "outcome": res.outcome,
                              "detected_records": sum(o == FAIL_POLICY for o in res.record_outcomes.values()),
                              "covered_records": len(set(slots) & bad),
                              "missing_records": sum(o == INCONCLUSIVE for o in res.record_outcomes.values()),
                              "record_outcomes": res.record_outcomes,
                              "bytes": res.total_network_bytes, "cpu_ms": res.cpu_ms, "requests": len(res.requests)})
    rows = []
    for m in METHODS:
        row = summarize_rounds(m, seed, f"reactive_eps{eps}", dimension, budget, traces[m])
        row["eps"] = eps
        row["withheld_rounds"] = sum(bool(t["withholding_targets"]) for t in traces[m])
        rows.append(row)
    return {"seed": seed, "semantic_checks": verified, "rows": rows}


def _job(args):
    return run_seed(*args)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path(r".\experiments\e3_reactive\results"))
    ap.add_argument("--seeds", type=int, default=100)
    ap.add_argument("--seed-start", type=int, default=230001)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    write_json(a.out / "manifest.json", {
        "config": {k: str(v) for k, v in vars(a).items()},
        "methods": list(METHODS), "eps": list(EPS), "numpy": np.__version__,
        "source_hashes": {str(p): file_hash(p) for p in [
            Path(__file__), Path(r".\experiments\pba_v3\v5_scheduler.py"),
            Path(r".\experiments\pba_v3\repository.py"), Path(r".\experiments\pba_v3\verify.py")]}})
    started = time.perf_counter()
    rows, checks = [], 0
    jobs = [(s, e) for s in range(a.seed_start, a.seed_start + a.seeds) for e in EPS]
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(_job, j) for j in jobs]
        for done, fu in enumerate(as_completed(futs), 1):
            r = fu.result(); rows.extend(r["rows"]); checks += r["semantic_checks"]
            if done % 40 == 0 or done == len(jobs):
                print(f'{{"done":{done},"total":{len(jobs)},"elapsed":{round(time.perf_counter()-started,1)}}}', flush=True)
    write_json(a.out / "rows.json", rows)
    # means + degradation
    means, paired = {}, {}
    by = {}
    for r in rows:
        means.setdefault(f"eps{r['eps']}/{r['method']}", []).append(r)
        by[(r["eps"], r["seed"], r["method"])] = r["integrity_tdr"]
    out = {}
    for k, rs in means.items():
        out[k] = {f: float(np.mean([x[f] for x in rs if x[f] is not None]))
                  for f in ("integrity_tdr", "record_tdr", "bytes", "withheld_rounds", "false_fail_rounds")}
    print("\n%-8s%-12s%10s%12s%14s%12s" % ("eps", "method", "TDR", "bytes_KB", "withheld", "falseFAIL"))
    for e in EPS:
        for m in METHODS:
            r = out[f"eps{e}/{m}"]
            print("%-8s%-12s%10.4f%12.0f%14.1f%12.2f" % (e, m, r["integrity_tdr"], r["bytes"] / 1e3, r["withheld_rounds"], r["false_fail_rounds"]))
    print("\ndegradation vs fixed trajectory (eps=0), paired by seed")
    deg = {}
    for e in EPS[1:]:
        for m in METHODS:
            d = np.array([by[(e, s, m)] - by[(0.0, s, m)] for s in range(a.seed_start, a.seed_start + a.seeds)
                          if by.get((e, s, m)) is not None and by.get((0.0, s, m)) is not None])
            if len(d):
                idx = np.random.default_rng(77).integers(0, len(d), (20000, len(d)))
                ci = np.percentile(d[idx].mean(1), [1.25, 98.75])
            else:
                ci = (np.nan, np.nan)
            deg[f"eps{e}/{m}"] = {"delta": float(d.mean()), "ci97_5": [float(x) for x in ci], "n": int(len(d))}
            print(f"  eps={e} {m:<10} {d.mean():+.4f}")
    write_json(a.out / "summary.json", {"means": out, "degradation": deg,
                                        "n_seeds": a.seeds, "methods": list(METHODS), "eps": list(EPS),
                                        "semantic_checks": checks, "elapsed_seconds": time.perf_counter() - started})


if __name__ == "__main__":
    main()