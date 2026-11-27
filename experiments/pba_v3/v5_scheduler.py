"""Authenticated, matched-trace scheduling decision experiment. See PROTOCOL.md."""
import argparse
import hashlib
import json
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import numpy as np
from .repository import Keys, make_fixture, tamper
from .verify import audit, PASS, INCONCLUSIVE, FAIL_POLICY
from .v5_common import METHODS, Scheduler, bootstrap, file_hash, write_json

SCENARIOS = ("honest", "integrity_only", "mixed", "recovery", "moving_integrity",
             "moving_mixed", "withholding_only")
METRICS = ("integrity_tdr", "record_tdr", "coverage", "availability_observation_rate",
           "missing_finding_rounds", "inconclusive_only_rounds", "missed_attack_rounds",
           "bytes", "cpu_ms", "record_attempts", "missing_requests")


def placement(seed, round_id, scenario):
    order = np.random.default_rng(np.random.SeedSequence([seed, 91002])).permutation(30).tolist()
    withholding = set(order[2:4])
    integrity = set(order[:2])
    if scenario.startswith("moving"):
        pool = order[:2] + order[4:]
        at = (2 * ((max(9, round_id)-9)//4)) % len(pool)
        integrity = {pool[at], pool[(at+1)%len(pool)]}
    if round_id < 9 or scenario in ("honest", "withholding_only"):
        integrity = set()
    if round_id < 9 or scenario in ("honest", "integrity_only", "moving_integrity"):
        withholding = set()
    if scenario == "recovery" and round_id >= 33:
        withholding = set()
    assert not (integrity & withholding)
    return integrity, withholding


def summarize_rounds(method, seed, scenario, dimension, budget, trace):
    active = [r for r in trace if r["integrity_targets"]]
    avail = [r for r in trace if r["withholding_targets"]]
    corrupted = sum(len(r["integrity_targets"]) for r in active)
    detected = [r for r in active if r["detected_records"]]
    sumkey = lambda key: sum(r[key] for r in trace)
    recovery = []
    if scenario == "recovery":
        _, targets = placement(seed, 32, scenario)
        for c in sorted(targets):
            hits = [r["round"]-33 for r in trace if r["round"] >= 33 and c in r["slots"]]
            recovery.append({"slot": c, "latency": min(hits) if hits else None,
                             "censor_rounds": 28 if not hits else None})
    return {"method": method, "seed": seed, "scenario": scenario, "dimension": dimension,
            "budget": budget, "rounds": len(trace), "attacked_rounds": len(active),
            "integrity_tdr": len(detected)/len(active) if active else None,
            "record_tdr": sumkey("detected_records")/corrupted if corrupted else None,
            "coverage": sumkey("covered_records")/corrupted if corrupted else None,
            "availability_observation_rate": sum(bool(r["missing_records"]) for r in avail)/len(avail) if avail else None,
            "missing_finding_rounds": sum(bool(r["missing_records"]) for r in trace),
            "inconclusive_only_rounds": sum(r["outcome"] == INCONCLUSIVE for r in trace),
            "missed_attack_rounds": len(active)-len(detected),
            "first_detection_latency": detected[0]["round"]-active[0]["round"] if detected else None,
            "detection_censored": bool(active) and not detected,
            "false_fail_rounds": sum(bool(r["detected_records"]) for r in trace if not r["integrity_targets"]),
            "bytes": sumkey("bytes"), "cpu_ms": sumkey("cpu_ms"),
            "record_attempts": sum(len(r["slots"]) for r in trace),
            "missing_requests": sumkey("missing_records"),
            "requests": sumkey("requests"), "recovery": recovery}


def run_seed(seed, dimension=256, budget=3, rounds=60):
    keys = Keys.generate(list(range(30)))
    schedulers = {(s,m): Scheduler(m) for s in SCENARIOS for m in METHODS}
    traces = {(s,m): [] for s in SCENARIOS for m in METHODS}
    verified = 0
    for rid in range(1, rounds+1):
        base = make_fixture(round_id=rid, dimension=dimension, clients=30,
                            seed=seed*1000+rid, keys=keys)
        fixtures = {}
        # Integrity placement and the server snapshot are fixed before sampling.
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
                sch = schedulers[scenario, method]
                slots = sch.choose(seed, rid, budget)
                res = audit(f.source, f.trust, slots=slots)
                # Independent semantic map: prescribed mutation changes only
                # declared policy; missing is disjoint. Does not call verifier.
                expected = {c: FAIL_POLICY if c in bad else INCONCLUSIVE if c in missing else PASS for c in slots}
                assert res.record_outcomes == expected, (scenario, method, rid, expected, res.record_outcomes)
                verified += len(slots)
                sch.observe(res.record_outcomes)
                traces[scenario,method].append({"round": rid, "slots": slots,
                    "integrity_targets": sorted(bad), "withholding_targets": sorted(missing),
                    "outcome": res.outcome, "detected_records": sum(o == FAIL_POLICY for o in res.record_outcomes.values()),
                    "covered_records": len(set(slots)&bad),
                    "missing_records": sum(o == INCONCLUSIVE for o in res.record_outcomes.values()),
                    "record_outcomes": res.record_outcomes,
                    "bytes": res.total_network_bytes, "cpu_ms": res.cpu_ms, "requests": len(res.requests)})
    rows = [summarize_rounds(m,seed,s,dimension,budget,traces[s,m]) for s in SCENARIOS for m in METHODS]
    return {"seed": seed, "semantic_checks": verified, "rows": rows,
            "traces": {s: {m: traces[s,m] for m in METHODS} for s in SCENARIOS}}


def analyze(rows):
    groups = {(s,m): sorted([r for r in rows if r["scenario"]==s and r["method"]==m], key=lambda r:r["seed"])
              for s in SCENARIOS for m in METHODS}
    means, pairs = {}, {}
    for (s,m), part in groups.items():
        means[s+"/"+m] = {k: bootstrap([r[k] for r in part if r[k] is not None]) for k in METRICS}
        latency = [r["first_detection_latency"] for r in part if r["first_detection_latency"] is not None]
        means[s+"/"+m]["latency"] = {"conditional_mean": float(np.mean(latency)) if latency else None,
             "detected_seeds": len(latency), "censored_seeds": sum(r["detection_censored"] for r in part)}
        recovered = [x["latency"] for r in part for x in r["recovery"] if x["latency"] is not None]
        means[s+"/"+m]["recovery"] = {"conditional_mean": float(np.mean(recovered)) if recovered else None,
             "reinspected_targets": len(recovered), "censored_targets": sum(x["latency"] is None for r in part for x in r["recovery"])}
    for s in SCENARIOS:
        for left,right in (("neutral","uniform"),("neutral","separated"),("neutral","adaptive"),("separated","uniform")):
            a,b = groups[s,left],groups[s,right]
            assert [r["seed"] for r in a]==[r["seed"] for r in b]
            result = {}
            for k in METRICS:
                diffs = [x[k]-y[k] for x,y in zip(a,b) if x[k] is not None and y[k] is not None]
                result[k] = bootstrap(diffs)
            if s=="mixed" and left=="neutral" and right in ("uniform","separated"):
                result["primary_family_ci97_5"] = bootstrap([x["integrity_tdr"]-y["integrity_tdr"] for x,y in zip(a,b)],level=.975)
            pairs[s+"/"+left+"-"+right] = result
    crowdout = {}
    for m in METHODS:
        a,b = groups["mixed",m],groups["integrity_only",m]
        crowdout[m] = bootstrap([x["integrity_tdr"]-y["integrity_tdr"] for x,y in zip(a,b)])
    return {"means": means, "paired": pairs, "mixed_minus_integrity_only": crowdout}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--seeds",type=int,default=100)
    p.add_argument("--seed-start",type=int,default=220001)
    p.add_argument("--dimension",type=int,default=256)
    p.add_argument("--budget",type=int,default=3)
    p.add_argument("--workers",type=int,default=3)
    a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    inputs=[Path(__file__),Path(__file__).with_name("v5_common.py"),Path(__file__).with_name("verify.py"),Path(__file__).with_name("repository.py")]
    metadata={"config":vars(a)|{"out":str(a.out)},"numpy":np.__version__,"source_hashes":{str(x):file_hash(x) for x in inputs}}
    write_json(a.out/"manifest.json",metadata)
    started=time.perf_counter()
    rows=[]
    checks=0
    with ProcessPoolExecutor(max_workers=a.workers) as executor:
        futures={executor.submit(run_seed,seed,a.dimension,a.budget):seed for seed in range(a.seed_start,a.seed_start+a.seeds)}
        for done,fut in enumerate(as_completed(futures),1):
            result=fut.result()
            write_json(a.out/f"seed_{result['seed']}.json",result)
            rows.extend(result["rows"])
            checks+=result["semantic_checks"]
            print(json.dumps({"done":done,"total":a.seeds,"seed":result["seed"],"elapsed_seconds":round(time.perf_counter()-started,1)}),flush=True)
    rows.sort(key=lambda r:(r["scenario"],r["method"],r["seed"]))
    write_json(a.out/"summary.json",analyze(rows)|{"rows":rows,"semantic_checks":checks,"elapsed_seconds":time.perf_counter()-started})
    print(json.dumps({"completed":True,"rows":len(rows),"semantic_checks":checks}),flush=True)

if __name__=="__main__":
    main()
