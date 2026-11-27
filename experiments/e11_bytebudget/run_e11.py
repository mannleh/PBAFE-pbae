# -*- coding: utf-8 -*-
"""E11 - common byte budget rerun (R3-7).

All four schedules receive the same per-round byte allowance instead of the
same number of inspected records. The allowance is calibrated per seed as one
three-record round on an honest fixture (fixed overhead + three average
marginal record costs), so an arm that inspects cheaper records can inspect
more of them and an arm that inspects expensive records inspects fewer.
"""
import argparse, json, statistics, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np

sys.path.insert(0, r".")
from experiments.pba_v3.repository import Keys, make_fixture, tamper
from experiments.pba_v3.verify import audit, PASS, INCONCLUSIVE, FAIL_POLICY
from experiments.pba_v3.v5_common import METHODS, Scheduler, bootstrap, file_hash, write_json
from experiments.pba_v3.v5_scheduler import SCENARIOS, placement

OUT = Path(r".\experiments\e11_bytebudget")
METRICS = ("integrity_tdr", "record_tdr", "coverage", "bytes", "records",
           "missing_rounds", "requests")


def calibrate(seed, dimension, keys):
    base = make_fixture(round_id=1, dimension=dimension, clients=30, seed=seed * 1000 + 1, keys=keys)
    one = {}
    for c in range(30):
        one[c] = audit(base.source, base.trust, slots=[c]).total_network_bytes
    b2 = audit(base.source, base.trust, slots=[0, 1]).total_network_bytes
    b3 = audit(base.source, base.trust, slots=[0, 1, 2]).total_network_bytes
    fixed = 2 * one[0] - b2
    costs = {c: max(1, one[c] - fixed) for c in range(30)}
    marginal = b3 - b2
    if abs(marginal - statistics.mean(costs.values())) > marginal:
        marginal = statistics.mean(costs.values())
    allowance = fixed + 3 * max(costs.values())
    return fixed, costs, allowance


def choose_byte(sch, seed, rid, allowance, fixed, costs, max_records=6):
    rng = np.random.default_rng(np.random.SeedSequence([seed, rid, 91001]))
    u = rng.uniform(np.finfo(float).tiny, 1, sch.clients)
    weights = np.ones(sch.clients) if sch.method == "uniform" else sch.risk + max(.05, 1 / sch.clients)
    priority = -np.log(u) / weights
    if sch.method != "separated":
        pool = sorted(range(sch.clients), key=lambda c: (priority[c], c))
    else:
        due = [c for c, when in sch.due.items() if when <= rid]
        retry = sorted(due, key=lambda c: (sch.due[c], -np.log(u[c]), c))[:1]
        eligible = [c for c in range(sch.clients) if c not in sch.due]
        pool = retry + sorted(eligible, key=lambda c: (priority[c], c)) + \
               sorted([c for c in range(sch.clients) if c not in retry and c in sch.due],
                      key=lambda c: (priority[c], c))
    chosen, spent = [], fixed
    for c in pool:
        if len(chosen) >= max_records:
            break
        if spent + costs[c] <= allowance:
            chosen.append(c)
            spent += costs[c]
    if not chosen:
        chosen = [pool[0]]
    # Residual-byte rule, identical for every arm: if the round spent less than
    # the ceiling (FAIL and INCONCLUSIVE responses carry no opening and no
    # aggregate replay), the leftover bytes go to the cheapest uninspected
    # record. This is what makes the ceiling bind on bytes rather than records.
    rest = sorted((c for c in range(sch.clients) if c not in chosen), key=lambda c: (costs[c], c))
    for c in rest:
        if len(chosen) >= max_records or spent + costs[c] > allowance:
            break
        chosen.append(c)
        spent += costs[c]
    return sorted(chosen)


def summarize(method, seed, scenario, allowance, trace, cal, carry_end):
    active = [r for r in trace if r["integrity_targets"]]
    corrupted = sum(len(r["integrity_targets"]) for r in active)
    sumkey = lambda k: sum(r[k] for r in trace)
    return {"method": method, "seed": seed, "scenario": scenario,
            "integrity_tdr": sum(bool(r["detected_records"]) for r in active) / len(active) if active else None,
            "record_tdr": sumkey("detected_records") / corrupted if corrupted else None,
            "coverage": sumkey("covered_records") / corrupted if corrupted else None,
            "bytes": sumkey("bytes"), "records": sumkey("records"),
            "requests": sumkey("requests"),
            "missing_rounds": sum(bool(r["missing_records"]) for r in trace),
            "allowance": allowance, "fixed": cal[0], "mean_cost": statistics.mean(cal[1].values()),
            "carry_end": carry_end,
            "records_mean": statistics.mean(r["records"] for r in trace)}


def run_seed(seed, dimension=256, rounds=60):
    keys = Keys.generate(list(range(30)))
    fixed, costs, allowance = calibrate(seed, dimension, keys)
    sched = {(s, m): Scheduler(m) for s in SCENARIOS for m in METHODS}
    traces = {(s, m): [] for s in SCENARIOS for m in METHODS}
    carry = {(s, m): 0.0 for s in SCENARIOS for m in METHODS}
    checks = 0
    for rid in range(1, rounds + 1):
        base = make_fixture(round_id=rid, dimension=dimension, clients=30,
                            seed=seed * 1000 + rid, keys=keys)
        fixtures = {}
        for scenario in SCENARIOS:
            bad, missing = placement(seed, rid, scenario)
            key = (tuple(sorted(bad)), tuple(sorted(missing)))
            if key not in fixtures:
                f = tamper(base, "declared_count_policy", tuple(sorted(bad))) if bad else base.clone()
                for c in missing:
                    f.source.pop(f"record/{c}/opening", None)
                fixtures[key] = f
            f = fixtures[key]
            for method in METHODS:
                sch = sched[scenario, method]
                budget_now = allowance + carry[scenario, method]
                slots = choose_byte(sch, seed, rid, budget_now, fixed, costs)
                res = audit(f.source, f.trust, slots=slots)
                expected = {c: FAIL_POLICY if c in bad else INCONCLUSIVE if c in missing else PASS for c in slots}
                assert res.record_outcomes == expected, (scenario, method, rid)
                checks += len(slots)
                sch.observe(res.record_outcomes)
                # Cumulative byte budget: unspent bytes are carried to the next
                # round, so over the run every arm receives the same allowance.
                carry[scenario, method] = max(-allowance,
                    min(2 * allowance, carry[scenario, method] + allowance - res.total_network_bytes))
                traces[scenario, method].append({
                    "round": rid, "slots": slots, "records": len(slots),
                    "integrity_targets": sorted(bad), "withholding_targets": sorted(missing),
                    "detected_records": sum(o == FAIL_POLICY for o in res.record_outcomes.values()),
                    "covered_records": len(set(slots) & bad),
                    "missing_records": sum(o == INCONCLUSIVE for o in res.record_outcomes.values()),
                    "bytes": res.total_network_bytes, "requests": len(res.requests)})
    rows = [summarize(m, seed, s, allowance, traces[s, m], (fixed, costs, allowance),
                      float(carry[s, m])) for s in SCENARIOS for m in METHODS]
    return {"seed": seed, "checks": checks, "rows": rows,
            "allowance": allowance, "fixed": fixed,
            "cost_summary": {"min": min(costs.values()), "max": max(costs.values()),
                             "mean": statistics.mean(costs.values())}}


def analyze(rows):
    groups = {(s, m): sorted([r for r in rows if r["scenario"] == s and r["method"] == m], key=lambda r: r["seed"])
              for s in SCENARIOS for m in METHODS}
    means, pairs = {}, {}
    for (s, m), part in groups.items():
        means[s + "/" + m] = {k: bootstrap([r[k] for r in part if r[k] is not None]) for k in METRICS}
        means[s + "/" + m]["records_mean"] = bootstrap([r["records_mean"] for r in part])
    for s in SCENARIOS:
        for left, right in (("neutral", "uniform"), ("neutral", "separated"), ("neutral", "adaptive"),
                            ("separated", "uniform"), ("adaptive", "uniform")):
            a, b = groups[s, left], groups[s, right]
            assert [r["seed"] for r in a] == [r["seed"] for r in b]
            d = {}
            for k in METRICS:
                diffs = [x[k] - y[k] for x, y in zip(a, b) if x[k] is not None and y[k] is not None]
                d[k] = bootstrap(diffs)
            pairs[s + "/" + left + "-" + right] = d
    return {"means": means, "paired": pairs}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seeds", type=int, default=20)
    p.add_argument("--seed-start", type=int, default=240001)
    p.add_argument("--dimension", type=int, default=256)
    p.add_argument("--workers", type=int, default=4)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    inputs = [Path(__file__), Path(r".\experiments\pba_v3\v5_common.py"),
              Path(r".\experiments\pba_v3\v5_scheduler.py"),
              Path(r".\experiments\pba_v3\verify.py"),
              Path(r".\experiments\pba_v3\repository.py")]
    write_json(a.out / "manifest.json", {"config": {k: str(v) for k, v in vars(a).items()},
                                         "numpy": np.__version__,
                                         "source_hashes": {str(x): file_hash(x) for x in inputs}})
    started = time.perf_counter()
    rows, checks = [], 0
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(run_seed, sd, a.dimension, 60): sd for sd in range(a.seed_start, a.seed_start + a.seeds)}
        for i, f in enumerate(as_completed(futs), 1):
            r = f.result()
            write_json(a.out / f"seed_{r['seed']}.json", r)
            rows.extend(r["rows"])
            checks += r["checks"]
            print(json.dumps({"done": i, "seed": r["seed"], "elapsed_s": round(time.perf_counter() - started, 1)}), flush=True)
    rows.sort(key=lambda r: (r["scenario"], r["method"], r["seed"]))
    write_json(a.out / "summary.json", analyze(rows) | {"rows": rows, "checks": checks,
                                                         "elapsed_s": time.perf_counter() - started})
    print(json.dumps({"completed": True, "rows": len(rows), "checks": checks}), flush=True)


if __name__ == "__main__":
    main()
