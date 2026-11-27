#!/usr/bin/env python3
"""Publication-candidate budget experiment using the PBA/2 verifier itself.

The attack trace is generated independently of each scheduler.  Each scheduler
reads the same committed round transcript, but only the selected evidence is
charged for spot audits.  No ground-truth anomaly is revealed to the adaptive
scheduler; risk scores change only after an observed verifier failure.
"""
import argparse, csv, json, math, time
from pathlib import Path
import numpy as np
from .repository import make_fixture, tamper
from .verify import (audit, PASS, FAIL_ROSTER, FAIL_POLICY,
                     FAIL_RESULT_REPLAY, INCONCLUSIVE)

METHODS=("no_audit","fixed_low","uniform","round_robin","adaptive",
         "periodic_full","fixed_high","policy_blind")
ATTACKS=("random","persistent","withholding")
FAILURES={FAIL_ROSTER, FAIL_POLICY, FAIL_RESULT_REPLAY}


def attack_trace(attack, seed, rounds=60, clients=30):
    rng=np.random.default_rng(seed); rows=[]
    for r in range(rounds):
        if attack=="random":
            ids=set(map(int,rng.choice(clients,2,replace=False))) if rng.random()<.35 else set()
            rows.append({"ids":ids,"kind":"record","withhold":False})
        elif attack=="persistent":
            rows.append({"ids":{0,1} if r>=8 else set(),"kind":"record","withhold":False})
        elif attack=="withholding":
            rows.append({"ids":{0,1} if r>=8 else set(),"kind":"record","withhold":True})
        else: raise ValueError(attack)
    return rows


def make_attack_round(event, round_id, seed, dimension=256, clients=30):
    fixture=make_fixture(round_id=round_id,dimension=dimension,clients=clients,
                         seed=seed)
    ids=tuple(sorted(event["ids"]))
    if event["withhold"] and ids:
        for cid in ids:
            fixture.source.pop(f"record/{cid}/opening",None)
        return fixture
    if ids:
        return tamper(fixture,"declared_count_policy",ids)
    return fixture


def schedule(method, round_id, clients, budget, rng, scores):
    if method=="no_audit": return "none",[]
    if method=="fixed_low": return "spot",sorted(map(int,rng.choice(clients,1,replace=False)))
    if method in ("uniform","policy_blind"):
        return "spot",sorted(map(int,rng.choice(clients,budget,replace=False)))
    if method=="round_robin": return "spot",[(round_id*budget+j)%clients for j in range(budget)]
    if method=="adaptive":
        # Exploration floor avoids certainty collapse; only observed failures
        # update scores, so this scheduler does not receive an oracle trace.
        floor=max(0.05,1.0/clients)
        weights=np.asarray(scores,dtype=float)+floor; weights/=weights.sum()
        return "spot",sorted(map(int,rng.choice(clients,budget,replace=False,p=weights)))
    if method=="periodic_full":
        return ("full",list(range(clients))) if (round_id+1)%10==0 else ("none",[])
    if method=="fixed_high": return "full",list(range(clients))
    raise ValueError(method)


def audit_fields(result):
    d=result.as_dict()
    return {"outcome":result.outcome,"aggregate_verified":result.aggregate_verified,
            "inconclusive_reason":result.inconclusive_reason,
            "total_network_bytes":result.total_network_bytes,"cpu_ms":result.cpu_ms,
            "wall_ms":result.wall_ms,"peak_memory_bytes":result.peak_memory_bytes,
            "records_processed":result.records_processed,"updates_processed":result.updates_processed,
            "request_bytes":result.request_bytes,"response_framing_bytes":result.response_framing_bytes,
            **{k:d[k] for k in d if k.endswith("_bytes_read")}}


def update_risk_scores(scores, result, slots):
    """Update adaptive risk from verifier-visible outcomes only.

    This function deliberately accepts no attack trace or ground-truth labels.
    An INCONCLUSIVE outcome is observable evidence of an availability problem,
    but it is not counted as an integrity detection in the evaluator.
    """
    for cid in slots:
        outcome=result.record_outcomes.get(cid)
        if outcome in FAILURES:
            scores[cid] += 1.0
        elif outcome == INCONCLUSIVE:
            scores[cid] += 0.5


def evaluate_round(event, result, scope, slots):
    """Compute evaluation-only labels after verification has completed.

    The attack trace is used here solely to score a controlled experiment. It
    is never passed to ``schedule`` or ``update_risk_scores``.
    """
    truth_ids=set(event["ids"])
    if not truth_ids:
        return {"covered":False,"record_detected":False,
                "full_scope_detected":False,"full_replay_detected":False,
                "inconclusive":False}
    if scope=="spot":
        covered=bool(truth_ids.intersection(slots))
        observed_failure=any(result.record_outcomes.get(cid) in FAILURES
                             for cid in truth_ids.intersection(slots))
        return {"covered":covered,
                "record_detected":covered and observed_failure,
                "full_scope_detected":False,
                "full_replay_detected":False,
                "inconclusive":covered and result.outcome==INCONCLUSIVE}
    if scope=="full":
        failure=result.outcome in FAILURES
        replay_failure=(result.replay_performed and
                        result.outcome==FAIL_RESULT_REPLAY)
        return {"covered":True,"record_detected":False,
                "full_scope_detected":failure,
                "full_replay_detected":replay_failure,
                "inconclusive":result.outcome==INCONCLUSIVE}
    return {"covered":False,"record_detected":False,
            "full_scope_detected":False,"full_replay_detected":False,
            "inconclusive":False}


def one(method, attack, seed, rounds=60, clients=30, budget=3, dimension=256):
    events=attack_trace(attack,seed,rounds,clients)
    audit_rng=np.random.default_rng(seed+7919); scores=np.zeros(clients,dtype=float)
    attack_round_indices=[r for r,e in enumerate(events) if e["ids"]]
    attack_rounds=len(attack_round_indices)
    attack_onset=min(attack_round_indices) if attack_round_indices else None
    covered_rounds=[]; record_detected_rounds=[]; full_scope_detected_rounds=[]
    full_replay_detected_rounds=[]; inconclusive_attack_rounds=[]
    inconclusive=0
    total_bytes=total_cpu=total_wall=0.0
    checks=spot_checks=full_checks=records_processed=updates_processed=0
    first=None; audit_outcomes={}; audit_calls=0
    t0=time.perf_counter()
    for r,event in enumerate(events):
        scope,slots=schedule(method,r,clients,budget,audit_rng,scores)
        if scope=="none": continue
        audit_calls+=1
        fixture=make_attack_round(event,r+1,seed*1000+r,dimension,clients)
        bound=(method!="policy_blind")
        result=audit(fixture.source,fixture.trust,slots=slots,full=(scope=="full"),bound=bound)
        if scope=="spot":
            checks+=len(slots); spot_checks+=len(slots)
        else:
            checks+=clients; full_checks+=1
        records_processed+=result.records_processed; updates_processed+=result.updates_processed
        total_bytes+=result.total_network_bytes; total_cpu+=result.cpu_ms; total_wall+=result.wall_ms
        audit_outcomes[str(r)]=audit_fields(result)
        if result.outcome==INCONCLUSIVE:
            inconclusive+=1
        evaluation=evaluate_round(event,result,scope,slots)
        if evaluation["covered"]:
            covered_rounds.append(r)
        if evaluation["inconclusive"]:
            inconclusive_attack_rounds.append(r)
        if evaluation["record_detected"]:
            record_detected_rounds.append(r)
        if evaluation["full_scope_detected"]:
            full_scope_detected_rounds.append(r)
        if evaluation["full_replay_detected"]:
            full_replay_detected_rounds.append(r)
        detected=evaluation["record_detected"] or evaluation["full_scope_detected"]
        if detected and first is None:
            first=r
        # Crucially, this call has no access to event["ids"].
        if method=="adaptive" and scope=="spot":
            update_risk_scores(scores,result,slots)
    record_tdr=(len(set(record_detected_rounds))/attack_rounds
                if attack_rounds else 0.0)
    full_scope_tdr=(len(set(full_scope_detected_rounds))/attack_rounds
                    if attack_rounds else 0.0)
    replay_tdr=(len(set(full_replay_detected_rounds))/attack_rounds
                if attack_rounds else 0.0)
    coverage=(len(set(covered_rounds))/attack_rounds if attack_rounds else 0.0)
    latency=(first-attack_onset) if first is not None and attack_onset is not None else None
    return {"method":method,"attack":attack,"seed":seed,"rounds":rounds,"clients":clients,
            "record_budget":budget,"checks":checks,"full_round_checks":full_checks,
            "spot_record_checks":spot_checks,"audit_calls":audit_calls,
            "attack_onset":attack_onset,"attack_rounds":attack_rounds,
            "covered_attack_rounds":len(set(covered_rounds)),
            "record_detected_attack_rounds":len(set(record_detected_rounds)),
            "full_scope_detected_attack_rounds":len(set(full_scope_detected_rounds)),
            "full_replay_detected_attack_rounds":len(set(full_replay_detected_rounds)),
            "detected_attack_rounds":len(set(record_detected_rounds)|set(full_scope_detected_rounds)),
            "record_level_tdr":record_tdr if method not in ("fixed_high","periodic_full") else 0.0,
            "full_scope_tdr":full_scope_tdr if method in ("fixed_high","periodic_full") else 0.0,
            "full_round_tdr":full_scope_tdr if method in ("fixed_high","periodic_full") else 0.0,
            "full_replay_result_tdr":replay_tdr,
            "attack_coverage":coverage,
            "first_detection_observed":first is not None,
            "first_detection_latency":latency,
            "inconclusive_attack_rounds":len(set(inconclusive_attack_rounds)),
            "bytes_read":int(total_bytes),
            "cpu_ms":total_cpu,"wall_ms":total_wall,"inconclusive":inconclusive,
            "records_processed":records_processed,"updates_processed":updates_processed,
            "elapsed_ms":(time.perf_counter()-t0)*1000,"audit_outcomes":audit_outcomes}


def mean_ci(values):
    a=np.asarray([v for v in values if v is not None and np.isfinite(v)],dtype=float)
    m=float(a.mean()) if len(a) else 0.0
    ci=float(1.96*a.std(ddof=1)/math.sqrt(len(a))) if len(a)>1 else 0.0
    return m,ci


def run(out, seeds=100, seed_start=0, budget=3):
    out.mkdir(parents=True,exist_ok=True); rows=[]
    for attack in ATTACKS:
        for method in METHODS:
            for s in range(seeds):
                rows.append(one(method,attack,100000+seed_start+s,budget=budget))
                if len(rows)%50==0: print(json.dumps({"rows":len(rows)}),flush=True)
    with (out/"budget_audit_results_release.csv").open("w",newline="",encoding="utf8") as h:
        # Keep nested per-round verifier details in JSON, not CSV cells.
        flat=[]
        for x in rows:
            y=dict(x); y.pop("audit_outcomes",None); flat.append(y)
        w=csv.DictWriter(h,fieldnames=list(flat[0])); w.writeheader(); w.writerows(flat)
    summary=[]
    for attack in ATTACKS:
        for method in METHODS:
            part=[x for x in rows if x["attack"]==attack and x["method"]==method]
            item={"attack":attack,"method":method,"n":len(part)}
            for key in ("record_level_tdr","full_scope_tdr","full_round_tdr",
                        "full_replay_result_tdr","attack_coverage","bytes_read",
                        "cpu_ms","wall_ms","first_detection_latency",
                        "first_detection_observed","inconclusive",
                        "inconclusive_attack_rounds","checks","spot_record_checks",
                        "full_round_checks","audit_calls","records_processed",
                        "updates_processed"):
                m,ci=mean_ci([x[key] for x in part]); item[key+"_mean"]=m; item[key+"_95ci"]=ci
            item["detected_latency_n"]=sum(bool(x["first_detection_observed"]) for x in part)
            item["latency_censored_n"]=len(part)-item["detected_latency_n"]
            summary.append(item)
    result={"status":"measured-candidate; corrected-observable-feedback; pending independent review",
            "protocol":"PBA/2","configuration":{"rounds":60,"clients":30,
            "record_budget":budget,"dimension":256,"seeds":seeds,"seed_start":seed_start,
            "same_attack_trace_across_methods":True,"adaptive_oracle_leakage":False,
            "adaptive_feedback":"verifier.record_outcomes_only",
            "latency":"actual_attack_onset; nondetection_censored",
            "metric_definitions":{"record_level_tdr":"detected attacked rounds whose sampled anomalous record returned a FAIL outcome",
                "full_scope_tdr":"detected attacked rounds with a scheduled full-audit FAIL outcome; not necessarily result replay",
                "full_replay_result_tdr":"attacked rounds with replay_performed and FAIL_RESULT_REPLAY",
                "attack_coverage":"attacked rounds whose relevant evidence was scheduled",
                "inconclusive":"all audit calls returning INCONCLUSIVE_EVIDENCE"},
            "actual_verifier_invocations":True,"full_replay_reads_all_30":True},
            "summary":summary,"rows":rows}
    (out/"budget_audit_results_release.json").write_text(json.dumps(result,indent=2),encoding="utf8")
    print(json.dumps({"rows":len(rows),"seeds":seeds,"seed_start":seed_start},indent=2))

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--out",type=Path,required=True)
    p.add_argument("--seeds",type=int,default=100); p.add_argument("--seed-start",type=int,default=0)
    p.add_argument("--budget",type=int,default=3)
    a=p.parse_args(); run(a.out,a.seeds,a.seed_start,a.budget)
