"""Mixed evidence -> observed scheduling -> no-oracle response, bounded v6 study.

Training loop is adapted from v5_response.run_arm without changing its learning,
aggregation, audit, scheduler, or reject-and-retain mechanisms. The only new
intervention removes evidence before the challenge; labels enter accounting only.
See results/bridge_v6_20261023/PROTOCOL.md for the frozen analysis plan.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import time
for _name in ("OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "OMP_NUM_THREADS"):
    os.environ[_name] = "1"
import numpy as np
from . import flcore
from .codec import SCALE
from .repository import Keys
from .run_c_consequence import DROPPED_CLIENTS, load
from .verify import INCONCLUSIVE, PASS, audit
from .v5_response import reject_round, next_model, published_aggregate, build_training_fixture
from .v5_common import bootstrap, file_hash, write_json

SCENARIOS = ("mixed_recovery", "withholding_recovery")
METHODS = ("noaudit", "uniform", "adaptive", "neutral", "separated")
_DATA_CACHE = {}


def withholding_slots(seed, clients=30):
    pool = [c for c in range(clients) if c not in DROPPED_CLIENTS]
    return sorted(map(int, np.random.default_rng(np.random.SeedSequence([seed, 96103])).choice(pool, 2, replace=False)))


def withhold(fixture, slots):
    removed = []
    for c in slots:
        state = fixture.obj(f"record/{c}/state")
        name = f"record/{c}/" + ("opening" if state["receipt_digest"] is not None else "disposition")
        if name not in fixture.source:
            raise AssertionError("fixture missing evidence before intervention: " + name)
        del fixture.source[name]
        removed.append(name)
    return removed


def trace_metrics(trace, restore_round=41):
    longest = current = 0
    for r in trace:
        current = current + 1 if r["rejected"] else 0
        longest = max(longest, current)
    compliant = [r for r in trace if not r["attack_targets"]]
    recovery = [r["round"] - restore_round for r in trace
                if r["round"] >= restore_round and not r["rejected"]]
    return {
        "applied_violating_rounds": sum(bool(r["attack_targets"]) and not r["rejected"] for r in trace),
        "prevented_violating_rounds": sum(bool(r["attack_targets"]) and r["rejected"] for r in trace),
        "compliant_rounds_retained": sum(r["rejected"] for r in compliant),
        "compliant_missing_retained": sum(r["rejected"] and r["outcome"] == INCONCLUSIVE for r in compliant),
        "compliant_rounds": len(compliant),
        "missing_finding_rounds": sum(r["missing_requests"] > 0 for r in trace),
        "mixed_fail_missing_rounds": sum(bool(r["outcome"] and r["outcome"].startswith("FAIL_")) and r["missing_requests"] > 0 for r in trace),
        "inconclusive_only_rounds": sum(r["outcome"] == INCONCLUSIVE for r in trace),
        "longest_retention_streak": longest,
        "post_restore_first_apply_delay": min(recovery) if recovery else None,
        "post_restore_apply_censored": not bool(recovery),
        "discarded_steps_fraction": sum(r["local_steps"] for r in trace if r["rejected"]) / sum(r["local_steps"] for r in trace),
        "discarded_compliant_steps": sum(r["local_steps"] for r in compliant if r["rejected"]),
    }

def run_cell(scenario, method, seed, data, rounds=60, selected=10, hidden=32, lr=.03,
             attack_start=20, attack_end=60, missing_start=20, missing_end=40,
             model_seed=None, selection_seed=None, full=False):
    if scenario not in SCENARIOS or method not in METHODS:
        raise ValueError((scenario, method))
    from .v5_common import Scheduler
    z, clients = data
    Xtr, ytr = z["X_train"], z["y_train"]
    Xte, yte = z["X_test"], z["y_test"]
    client_count = len(clients)
    if client_count <= max(DROPPED_CLIENTS) or not 0 < selected <= client_count:
        raise ValueError("client population incompatible with fixed attack")
    if model_seed is None and selection_seed is None:
        init_rng = selection_rng = np.random.default_rng(seed)
    else:
        init_rng = np.random.default_rng(seed if model_seed is None else model_seed)
        selection_rng = np.random.default_rng(seed if selection_seed is None else selection_seed)
    dimension = Xtr.shape[1]
    w = np.concatenate([init_rng.normal(0, .05, dimension * hidden), np.zeros(hidden),
                        init_rng.normal(0, .05, hidden), np.zeros(1)])
    initial_hash = hashlib.sha256(w.tobytes()).hexdigest()
    counts_all = [len(block) for block in clients]
    if min(counts_all) < 1:
        raise ValueError("empty training client")
    class_weights = {label: len(ytr) / (2 * max(1, int((ytr == label).sum())))
                     for label in (0, 1)}
    audited = method != "noaudit"
    budget = client_count if full else 3
    withholding_ids = withholding_slots(seed, client_count)
    scheduler = Scheduler(method, clients=client_count) if audited else None
    keys = Keys.generate(list(range(client_count))) if audited else None
    history, round_rows, schedule = [], [], []
    totals = dict(
        attack_rounds=0, attacked_updates_applied=0, attacked_records_applied=0,
        prevented_bad_rounds=0, rejected_rounds=0, honest_rounds_rejected=0,
        audit_calls=0, full_audit_calls=0, actual_replays=0, aggregate_verified=0,
        inconclusive_calls=0, audit_requests=0, audit_missing_requests=0,
        audit_request_bytes=0, audit_response_payload_bytes=0,
        audit_response_framing_bytes=0, audit_total_bytes=0,
        audit_cpu_ms=0.0, audit_wall_ms=0.0, training_wall_ms=0.0,
        evidence_build_wall_ms=0.0, local_training_steps=0, local_rows_processed=0,
        discarded_training_steps=0, discarded_rows_processed=0,
        application_upload_payload_bytes=0, application_download_payload_bytes=0,
        candidate_download_payload_bytes=0, response_extra_payload_bytes=0,
        records_processed=0, updates_processed=0,
    )
    for r in range(rounds):
        before_model_hash = hashlib.sha256(w.tobytes()).hexdigest()
        chosen = sorted(map(int, selection_rng.choice(client_count, selected, replace=False)))
        schedule.append(chosen)
        start = time.perf_counter_ns()
        vectors, counts = [], []
        rows_processed = 0
        for cid in chosen:
            ids = np.asarray(clients[cid], dtype=int)
            local_rng = np.random.default_rng(np.random.SeedSequence([seed, r, cid, 71]))
            vectors.append(flcore.local_update(w, Xtr[ids], ytr[ids], hidden, local_rng,
                                              lr=lr, class_weights=class_weights))
            counts.append(counts_all[cid])
            rows_processed += min(128, len(ids))
        training_ms = (time.perf_counter_ns() - start) / 1e6
        totals["training_wall_ms"] += training_ms
        totals["local_training_steps"] += len(chosen)
        totals["local_rows_processed"] += rows_processed
        # Model broadcast is float64; fixed-point uploaded updates are int64.
        # These are application payload counts, not TCP/IP/TLS wire traffic.
        totals["application_upload_payload_bytes"] += len(chosen) * len(w) * 8
        totals["application_download_payload_bytes"] += len(chosen) * len(w) * 8
        totals["candidate_download_payload_bytes"] += len(w) * 8
        active = scenario == "mixed_recovery" and attack_start <= r < attack_end
        aggregate = published_aggregate(vectors, counts, chosen, active)
        outcome, slots, record_outcomes = None, [], {}
        audit_bytes, audit_requests, missing_requests = 0, 0, 0
        unavailable = withholding_ids if missing_start <= r < missing_end else []
        withheld_objects, request_trace = [], []
        request_bytes = payload_bytes = framing_bytes = 0
        if audited:
            start = time.perf_counter_ns()
            f = build_training_fixture(w, vectors, counts, chosen, client_count, seed,
                                       r + 1, keys, active, aggregate)
            totals["evidence_build_wall_ms"] += (time.perf_counter_ns() - start) / 1e6
            # Evidence removal is fixed before the scheduler challenge. Accepted
            # records lose their opening; absent records lose their signed close.
            # Neither the committed state nor the candidate is changed.
            withheld_objects = withhold(f, unavailable)
            slots = scheduler.choose(seed, r + 1, budget)
            res = audit(f.source, f.trust, slots=slots, full=full)
            outcome, record_outcomes = res.outcome, res.record_outcomes
            scheduler.observe(record_outcomes)
            request_trace = list(res.requests)
            request_bytes = res.request_bytes
            payload_bytes = sum(res.bytes.values())
            framing_bytes = res.response_framing_bytes
            totals["audit_calls"] += 1
            totals["full_audit_calls"] += int(full)
            totals["actual_replays"] += int(res.replay_performed)
            totals["aggregate_verified"] += int(res.aggregate_verified)
            totals["inconclusive_calls"] += int(outcome == INCONCLUSIVE)
            audit_requests = len(res.requests)
            # Count actual Reader missing responses, including mixed FAIL plus
            # missing outcomes; do not infer from the overall outcome alone.
            missing_requests = sum(reason.startswith("missing:")
                                   for reason in res.inconclusive_reason)
            audit_bytes = res.total_network_bytes
            totals["audit_requests"] += audit_requests
            totals["audit_missing_requests"] += missing_requests
            totals["audit_request_bytes"] += res.request_bytes
            totals["audit_response_payload_bytes"] += sum(res.bytes.values())
            totals["audit_response_framing_bytes"] += res.response_framing_bytes
            totals["audit_total_bytes"] += audit_bytes
            totals["audit_cpu_ms"] += res.cpu_ms
            totals["audit_wall_ms"] += res.wall_ms
            totals["records_processed"] += res.records_processed
            totals["updates_processed"] += res.updates_processed
        rejected = reject_round(outcome)
        w = next_model(w, aggregate, outcome)
        # Ground truth enters only after the controller has committed its action.
        targets = sorted(set(chosen).intersection(DROPPED_CLIENTS)) if active else []
        attacked = bool(targets)
        totals["attack_rounds"] += int(attacked)
        totals["attacked_updates_applied"] += int(attacked and not rejected)
        totals["attacked_records_applied"] += len(targets) if not rejected else 0
        totals["prevented_bad_rounds"] += int(attacked and rejected)
        totals["rejected_rounds"] += int(rejected)
        totals["honest_rounds_rejected"] += int(not attacked and rejected)
        totals["discarded_training_steps"] += len(chosen) if rejected else 0
        totals["discarded_rows_processed"] += rows_processed if rejected else 0
        round_rows.append(dict(round=r + 1, chosen=chosen, attack_targets=targets,
                               previous_model_sha256=before_model_hash,
                               applied_model_sha256=hashlib.sha256(w.tobytes()).hexdigest(),
                               audit_slots=list(map(int, slots)), outcome=outcome,
                               record_outcomes={str(k): v for k, v in record_outcomes.items()},
                               rejected=rejected, audit_bytes=audit_bytes,
                               audit_requests=audit_requests, missing_requests=missing_requests,
                               trained_rows=rows_processed, local_steps=len(chosen),
                               withholding_slots=list(unavailable), withheld_objects=withheld_objects,
                               requests=request_trace, request_bytes=request_bytes,
                               payload_bytes=payload_bytes, framing_bytes=framing_bytes))
        if r % 10 == 9 or r == rounds - 1:
            history.append(dict(round=r + 1, **flcore.metrics(
                yte, (flcore.predict(w, Xte, hidden) >= .5).astype(int))))
    assert totals["attack_rounds"] == (totals["attacked_updates_applied"]
                                       + totals["prevented_bad_rounds"])
    assert totals["audit_total_bytes"] == (totals["audit_request_bytes"]
        + totals["audit_response_payload_bytes"] + totals["audit_response_framing_bytes"])
    return dict(scenario=scenario, method=method, seed=int(seed), rounds=rounds, audit_budget=budget if audited else 0,
                withholding_ids=withholding_ids, bridge=trace_metrics(round_rows),
                response_policy="reject FAIL/INCONCLUSIVE; retain previous model; no replacement",
                final={k: v for k, v in history[-1].items() if k != "round"},
                trajectory=history, totals=totals, round_rows=round_rows,
                initial_model_sha256=initial_hash,
                final_model_sha256=hashlib.sha256(w.tobytes()).hexdigest(),
                selection_schedule_sha256=hashlib.sha256(json.dumps(schedule).encode()).hexdigest(),
                dimension=len(w), clients=client_count, train_rows=len(ytr), test_rows=len(yte))



def _job(job):
    scenario, method, seed, data_dir, rounds = job
    if data_dir not in _DATA_CACHE:
        _DATA_CACHE[data_dir] = load(data_dir)
    return run_cell(scenario, method, seed, _DATA_CACHE[data_dir], rounds=rounds)


def analyze(folder):
    cfg = json.loads((folder / "config.json").read_text())
    done = json.loads((folder / "COMPLETE.json").read_text())
    rows = [json.loads(x) for x in (folder / "rows.jsonl").read_text().splitlines()]
    assert done["completed"] == done["expected"] == len(rows)
    seeds = list(range(cfg["seed_start"], cfg["seed_start"] + cfg["seeds"]))
    means, groups, paired = {}, {}, {}
    for scenario in SCENARIOS:
        for method in METHODS:
            group = sorted([r for r in rows if r["scenario"] == scenario and r["method"] == method], key=lambda r:r["seed"])
            assert [r["seed"] for r in group] == seeds
            groups[scenario,method] = group
            metrics = {}
            for section, keys in (("bridge", ("applied_violating_rounds", "prevented_violating_rounds", "compliant_rounds_retained", "longest_retention_streak", "discarded_steps_fraction", "missing_finding_rounds", "mixed_fail_missing_rounds", "inconclusive_only_rounds", "discarded_compliant_steps")),
                                  ("totals", ("audit_total_bytes", "discarded_training_steps", "rejected_rounds", "attack_rounds", "local_training_steps")),
                                  ("final", ("f1", "balanced_accuracy", "precision", "recall"))):
                for key in keys:
                    metrics[key] = bootstrap([r[section][key] for r in group])
            delays = [r["bridge"]["post_restore_first_apply_delay"] for r in group if not r["bridge"]["post_restore_apply_censored"]]
            metrics["post_restore_first_apply_delay"] = dict(conditional_mean=float(np.mean(delays)) if delays else None,
                observed=len(delays), censored=len(group)-len(delays), window_rounds=20)
            means[scenario+"/"+method] = metrics
        for seed in seeds:
            part = [r for r in rows if r["scenario"] == scenario and r["seed"] == seed]
            assert len({r["initial_model_sha256"] for r in part}) == 1
            assert len({r["selection_schedule_sha256"] for r in part}) == 1
    # Three prespecified primary contrasts form one Bonferroni family.
    primaries = (("mixed_recovery", "neutral", "adaptive", "compliant_rounds_retained", "bridge"),
                 ("mixed_recovery", "neutral", "uniform", "applied_violating_rounds", "bridge"),
                 ("mixed_recovery", "separated", "neutral", "longest_retention_streak", "bridge"))
    for scenario in SCENARIOS:
        for left,right in (("neutral","adaptive"),("neutral","uniform"),("separated","neutral")):
            a,b = groups[scenario,left],groups[scenario,right]
            result = {}
            for key in ("applied_violating_rounds", "compliant_rounds_retained", "longest_retention_streak", "discarded_steps_fraction"):
                result[key] = bootstrap([x["bridge"][key]-y["bridge"][key] for x,y in zip(a,b)])
            result["f1"] = bootstrap([x["final"]["f1"]-y["final"]["f1"] for x,y in zip(a,b)])
            for s,l,r,key,section in primaries:
                if (scenario,left,right) == (s,l,r):
                    result["primary"] = dict(metric=key, **bootstrap([x[section][key]-y[section][key] for x,y in zip(a,b)], level=1-.05/3))
            paired[scenario+"/"+left+"-"+right] = result
    summary = dict(n_runs=len(rows), n_seeds=len(seeds), means=means, paired=paired,
                   inference_scope="training/scheduling seed variation; one fixed data partition; no population generalization",
                   primary_family_size=3, primary_confidence=1-.05/3,
                   ci_method="20000 paired seed percentile bootstrap resamples", source="all completed rows; no exclusions")
    write_json(folder/"summary.json", summary)
    return summary


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--data-dir", type=Path, default=Path("data/unsw_official_subset_v3"))
    p.add_argument("--seeds", type=int, default=20)
    p.add_argument("--seed-start", type=int, default=310001)
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--rounds", type=int, default=60)
    p.add_argument("--analyze-only", action="store_true")
    args=p.parse_args()
    if args.analyze_only:
        print(json.dumps({"n_runs":analyze(args.out)["n_runs"]})); return
    if args.seeds < 1 or args.workers < 1 or not 1 <= args.rounds <= 60:
        p.error("positive seeds/workers and rounds 1..60 required")
    args.out.mkdir(parents=True, exist_ok=False)
    cfg = vars(args).copy()
    cfg.update(out=str(args.out.resolve()), data_dir=str(args.data_dir.resolve()), status="RUNNING",
               attack_rounds=[21,60], missing_rounds=[21,40], restoration_round=41,
               scenarios=list(SCENARIOS), methods=list(METHODS), budget=3,
               timing_scope="local diagnostics only; not deployment measurements")
    paths=[Path(__file__).with_name(name) for name in
           ("v6_bridge.py","v5_response.py","v5_common.py","flcore.py","verify.py","codec.py","repository.py","run_c_consequence.py")]
    cfg["source_sha256"]={str(p.resolve()):file_hash(p) for p in paths}
    cfg["data_sha256"]={name:file_hash(args.data_dir/name) for name in ("unsw_subset.npz","client_indices.json")}
    cfg["numpy_version"]=np.__version__
    write_json(args.out/"config.json",cfg)
    jobs=[(s,m,seed,str(args.data_dir.resolve()),args.rounds)
          for seed in range(args.seed_start,args.seed_start+args.seeds) for s in SCENARIOS for m in METHODS]
    count=0
    try:
        with (args.out/"rows.jsonl").open("x",encoding="utf8") as checkpoint:
            with ProcessPoolExecutor(max_workers=args.workers) as pool:
                futures=[pool.submit(_job,j) for j in jobs]
                for future in as_completed(futures):
                    row=future.result()
                    checkpoint.write(json.dumps(row,separators=(",",":"))+"\n")
                    checkpoint.flush(); os.fsync(checkpoint.fileno()); count+=1
                    print(json.dumps(dict(completed=count,total=len(jobs),seed=row["seed"],scenario=row["scenario"],method=row["method"],f1=row["final"]["f1"],**row["bridge"])),flush=True)
    except BaseException as exc:
        write_json(args.out/"FAILED.json",dict(error=repr(exc),completed=count,expected=len(jobs)))
        raise
    write_json(args.out/"COMPLETE.json",dict(status="COMPLETED",completed=count,expected=len(jobs)))
    analyze(args.out)


if __name__ == "__main__":
    main()
