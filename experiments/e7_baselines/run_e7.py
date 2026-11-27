# -*- coding: utf-8 -*-
"""E7 — stronger budget-aware baselines (R1-1/R1-10/R3-1/R3-2).

Adds two schedulers to the FROZEN v5 scheduling study without editing it:
  * ucb        — top-b by UCB score  risk/count + c*sqrt(log t / count)
  * epsgreedy  — with prob eps sample uniformly, else top-b by risk
Both treat INCONCLUSIVE as an integrity risk (like adaptive), so they are
strictly stronger budget-aware competitors. Reuses v5_scheduler.run_seed /
analyze by patching their module globals (METHODS, Scheduler) inside each worker;
placement, fixtures, semantic oracle, metrics are untouched.

Run: python -m experiments.e7_baselines.run_e7 --seeds 100 --workers 6
"""
from __future__ import annotations
import argparse, os, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

for _n in ("OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "OMP_NUM_THREADS"):
    os.environ[_n] = "1"
sys.path.insert(0, r".")
import numpy as np
from experiments.pba_v3 import v5_scheduler as R
from experiments.pba_v3.v5_common import Scheduler, bootstrap, file_hash, write_json
from experiments.pba_v3.verify import INCONCLUSIVE

METHODS6 = ("uniform", "adaptive", "neutral", "separated", "ucb", "epsgreedy")


class ExtScheduler(Scheduler):
    """Base four methods unchanged; ucb / epsgreedy added."""

    def __init__(self, method, clients=30, eps=.15, c=1.0):
        base = method if method in ("uniform", "adaptive", "neutral", "separated") else "uniform"
        super().__init__(base, clients)
        self.ext, self.eps, self.c = method, eps, c
        self.counts = np.zeros(clients)
        self.t = 0

    def choose(self, seed, round_id, budget):
        if self.ext not in ("ucb", "epsgreedy"):
            return super().choose(seed, round_id, budget)
        self.t += 1
        rng = np.random.default_rng(np.random.SeedSequence([seed, round_id, 91001]))
        u = rng.uniform(np.finfo(float).tiny, 1, self.clients)
        mean = self.risk / np.maximum(self.counts, 1)
        if self.ext == "ucb":
            score = mean + self.c * np.sqrt(np.log(self.t + 1) / np.maximum(self.counts, 1))
            pick = list(map(int, np.argsort(-score, kind="stable")[:budget]))
        else:
            if rng.random() < self.eps:
                pick = list(map(int, rng.choice(self.clients, budget, replace=False)))
            else:
                score = self.risk + max(.05, 1 / self.clients) + 1e-9 * (-np.log(u))
                pick = list(map(int, np.argsort(-score, kind="stable")[:budget]))
        for c in pick:
            self.counts[c] += 1
        return sorted(pick)

    def observe(self, record_outcomes):
        if self.ext in ("ucb", "epsgreedy"):
            for c, o in record_outcomes.items():
                if o in ("FAIL_ROSTER", "FAIL_POLICY", "FAIL_RESULT_REPLAY") or str(o).startswith("FAIL_"):
                    self.risk[c] += 1
                elif o == INCONCLUSIVE:
                    self.risk[c] += .5
            return
        super().observe(record_outcomes)


def _job(seed):
    import experiments.pba_v3.v5_scheduler as RR
    RR.METHODS = METHODS6
    RR.Scheduler = ExtScheduler
    return RR.run_seed(seed, 256, 3, 60)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, default=Path(r".\experiments\e7_baselines\results"))
    p.add_argument("--seeds", type=int, default=100)
    p.add_argument("--seed-start", type=int, default=220001)
    p.add_argument("--workers", type=int, default=6)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    inputs = [Path(R.__file__), Path(R.__file__).with_name("v5_common.py"),
              Path(R.__file__).with_name("verify.py"), Path(R.__file__).with_name("repository.py"), Path(__file__)]
    write_json(a.out / "manifest.json", {"config": {k: str(v) for k, v in vars(a).items()},
                                         "methods": list(METHODS6), "numpy": np.__version__,
                                         "source_hashes": {str(x): file_hash(x) for x in inputs}})
    started = time.perf_counter()
    rows, checks = [], 0
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(_job, s) for s in range(a.seed_start, a.seed_start + a.seeds)]
        for done, fu in enumerate(as_completed(futs), 1):
            res = fu.result()
            rows.extend(res["rows"]); checks += res["semantic_checks"]
            if done % 10 == 0 or done == a.seeds:
                print(f'{{"done":{done},"total":{a.seeds},"elapsed":{round(time.perf_counter()-started,1)}}}', flush=True)
    R.METHODS = METHODS6
    summary = R.analyze(rows)
    summary.update({"rows": rows, "semantic_checks": checks, "methods": list(METHODS6),
                    "elapsed_seconds": time.perf_counter() - started})
    write_json(a.out / "summary.json", summary)
    m = summary["means"]
    print("mixed TDR:", {k: round(m[f"mixed/{k}"]["integrity_tdr"]["mean"], 4) for k in METHODS6})
    print("mixed bytes:", {k: round(m[f"mixed/{k}"]["bytes"]["mean"], 1) for k in METHODS6})


if __name__ == "__main__":
    main()