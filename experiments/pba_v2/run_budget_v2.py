#!/usr/bin/env python3
"""Equal-budget audit scheduling with independent attack traces and measured PBA/2 costs."""
import argparse, csv, json, math
from pathlib import Path
import numpy as np
from .repository import build_round
from .verify import audit

METHODS=("no_audit","fixed_low","uniform","round_robin","adaptive","periodic_full","fixed_high","policy_blind")


def trace(attack, seed, rounds=60, k=30):
    rng=np.random.default_rng(seed); out=[]
    if attack=="random":
        for r in range(rounds):
            ids=set(map(int,rng.choice(k,2,replace=False))) if rng.random()<.35 else set()
            out.append({"ids":ids,"kind":"record"})
    elif attack=="persistent":
        for r in range(rounds): out.append({"ids":{0,1} if r>=8 else set(),"kind":"record"})
    elif attack=="withholding":
        for r in range(rounds): out.append({"ids":{0,1} if r>=8 else set(),"kind":"result","withhold":True})
    else: raise ValueError(attack)
    return out


def schedule(method,r,k,b,rng,scores):
    if method=="no_audit": return "spot",[]
    if method=="fixed_low": return "spot",sorted(map(int,rng.choice(k,1,replace=False)))
    if method in ("uniform","policy_blind"): return "spot",sorted(map(int,rng.choice(k,b,replace=False)))
    if method=="round_robin": return "spot",[(r*b+j)%k for j in range(b)]
    if method=="adaptive":
        # Non-oracular: scores are changed only by sampled verifier outcomes.
        floor=max(0.05, 1.0/k)
        weights=np.asarray(scores,dtype=float)+floor
        weights/=weights.sum()
        return "spot",sorted(map(int,rng.choice(k,b,replace=False,p=weights)))
    if method=="periodic_full": return ("full",list(range(k))) if (r+1)%10==0 else ("none",[])
    if method=="fixed_high": return "full",list(range(k))
    raise ValueError(method)


def calibrate(dimension=256,k=30,b=3):
    source,trust=build_round(clients=k,dimension=dimension,seed=90815)
    T=type("Trust",(),trust)()
    spot=audit(source,T,slots=list(range(b)))
    spot1=audit(source,T,slots=[0])
    full=audit(source,T,full=True)
    return {"spot":spot.as_dict(),"spot1":spot1.as_dict(),"full":full.as_dict()}


def one(method,attack,seed,costs,rounds=60,k=30,b=3):
    tr=trace(attack,seed,rounds,k); rng=np.random.default_rng(seed+7919); scores=np.zeros(k)
    attack_rounds=sum(bool(x["ids"]) for x in tr); detected_record=0; detected_full=0; inconclusive=0
    first=None; bytes_read=0; cpu=0; checks=0; full_checks=0; scope_checks=0
    for r,event in enumerate(tr):
        scope,selected=schedule(method,r,k,b,rng,scores)
        if scope=="none": continue
        if scope=="full": full_checks+=1; checks+=k; scope_checks+=1; metric=costs["full"]
        else: checks+=len(selected); scope_checks+=1; metric=costs["spot1"] if len(selected)==1 else costs["spot"]
        bytes_read+=metric["total_network_bytes"]; cpu+=metric["cpu_ms"]
        hit=bool(event["ids"].intersection(selected)) if scope=="spot" else bool(event["ids"])
        if event.get("withhold") and hit:
            inconclusive+=1; hit=False
        if hit:
            if first is None: first=r
            if scope=="full": detected_full+=1
            elif event["kind"]=="record" and method!="policy_blind": detected_record+=1
            # Only observed selected failures increase risk; no ground-truth leakage.
            if scope=="spot":
                for cid in event["ids"].intersection(selected): scores[cid]+=1
        elif scope=="full" and event["kind"]=="record" and event["ids"]:
            detected_full+=1
    return {"method":method,"attack":attack,"seed":seed,"rounds":rounds,"clients":k,"record_budget":b,
            "checks":checks,"full_round_checks":full_checks,"attack_rounds":attack_rounds,
            "record_level_tdr":detected_record/attack_rounds if attack_rounds else 0.0,
            "full_round_tdr":detected_full/attack_rounds if attack_rounds else 0.0,
            "first_detection_latency":first if first is not None else rounds,"bytes_read":bytes_read,
            "cpu_ms":cpu,"inconclusive":inconclusive,"scope_checks":scope_checks}


def mean_ci(vals):
    a=np.asarray(vals,float); mean=float(a.mean()) if len(a) else 0.0
    se=float(a.std(ddof=1)/math.sqrt(len(a))) if len(a)>1 else 0.0
    return mean,1.96*se


def run(out,seeds=100,seed_start=0):
    out.mkdir(parents=True,exist_ok=True); costs=calibrate(); (out/"pba2_cost_calibration.json").write_text(json.dumps(costs,indent=2),encoding="utf8")
    rows=[]
    for attack in ("random","persistent","withholding"):
        for method in METHODS:
            for s in range(seeds): rows.append(one(method,attack,100000+seed_start+s,costs))
    with (out/"budget_audit_results_final.csv").open("w",newline="",encoding="utf8") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    summary=[]
    for attack in ("random","persistent","withholding"):
        for method in METHODS:
            part=[x for x in rows if x["attack"]==attack and x["method"]==method]
            item={"attack":attack,"method":method,"n":len(part)}
            for key in ("record_level_tdr","full_round_tdr","bytes_read","cpu_ms","first_detection_latency","inconclusive"):
                m,ci=mean_ci([x[key] for x in part]); item[key+"_mean"]=m; item[key+"_95ci"]=ci
            summary.append(item)
    result={"protocol":"PBA/2","configuration":{"rounds":60,"clients":30,"record_budget":3,"dimension":256,"seeds":seeds,"seed_start":seed_start,"same_attack_trace_across_methods":True,"adaptive_oracle_leakage":False},"cost_calibration":costs,"summary":summary}
    (out/"budget_audit_results_final.json").write_text(json.dumps(result,indent=2),encoding="utf8"); print(json.dumps({"rows":len(rows),"seeds":seeds},indent=2))

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--out",type=Path,required=True); p.add_argument("--seeds",type=int,default=100); p.add_argument("--seed-start",type=int,default=0); a=p.parse_args(); run(a.out,a.seeds,a.seed_start)

