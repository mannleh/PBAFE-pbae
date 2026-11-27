"""Observation-only scheduling and paired seed analysis for the v5 decision study."""
import hashlib
import json
from pathlib import Path
import numpy as np
from .verify import PASS, INCONCLUSIVE, FAIL_ROSTER, FAIL_POLICY, FAIL_RESULT_REPLAY

METHODS = ("uniform", "adaptive", "neutral", "separated")
FAILURES = (FAIL_ROSTER, FAIL_POLICY, FAIL_RESULT_REPLAY)


class Scheduler:
    """No fixture, attack labels, future trace, or server keys are accepted here.

    Fixed per-round random priorities are shared across methods. `neutral` is
    the existing availability-neutral additive-risk rule, not a new algorithm.
    `separated` adds a three-round missing-evidence cooldown and at most one
    due availability retry; remaining slots use the same integrity-only risk.
    """
    def __init__(self, method, clients=30):
        if method not in METHODS:
            raise ValueError(method)
        self.method, self.clients = method, clients
        self.risk = np.zeros(clients)
        self.due = {}
        self.round_id = 0

    def choose(self, seed, round_id, budget):
        if not 0 < budget <= self.clients:
            raise ValueError("invalid record budget")
        self.round_id = round_id
        rng = np.random.default_rng(np.random.SeedSequence([seed, round_id, 91001]))
        u = rng.uniform(np.finfo(float).tiny, 1, self.clients)
        weights = np.ones(self.clients) if self.method == "uniform" else self.risk + max(.05, 1/self.clients)
        priority = -np.log(u) / weights
        order = lambda pool: sorted(pool, key=lambda c: (priority[c], c))
        if self.method != "separated":
            return sorted(order(range(self.clients))[:budget])
        due = [c for c, when in self.due.items() if when <= round_id]
        # Oldest due retry, with common random tie breaking; no permanent ban.
        retry = sorted(due, key=lambda c: (self.due[c], -np.log(u[c]), c))[:1]
        eligible = [c for c in range(self.clients) if c not in self.due]
        chosen = retry + order(eligible)[:budget-len(retry)]
        # For budgets exceeding the eligible pool, use the rest; all arms still
        # execute exactly b record checks and no method gets free probes.
        remaining = [c for c in range(self.clients) if c not in chosen]
        chosen += order(remaining)[:budget-len(chosen)]
        return sorted(chosen)

    def observe(self, record_outcomes):
        for c, outcome in record_outcomes.items():
            if outcome in FAILURES:
                self.risk[c] += 1
                self.due.pop(c, None)
            elif outcome == INCONCLUSIVE:
                if self.method == "adaptive":
                    self.risk[c] += .5
                if self.method == "separated":
                    self.due[c] = self.round_id + 3
            elif outcome == PASS:
                self.due.pop(c, None)


def bootstrap(values, level=.95, resamples=20000):
    """Percentile CI of a seed-level mean; paired comparisons pass differences."""
    x = np.asarray(values, dtype=float)
    if len(x) < 2:
        return {"n": len(x), "mean": float(x.mean()) if len(x) else None, "ci": None}
    rng = np.random.default_rng(776655)
    means = x[rng.integers(len(x), size=(resamples, len(x)))].mean(axis=1)
    q = (1-level)/2
    return {"n": len(x), "mean": float(x.mean()), "ci": np.quantile(means, [q,1-q]).tolist(),
            "confidence": level, "resamples": resamples, "unit": "matched seed"}


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf8")
