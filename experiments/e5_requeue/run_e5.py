# -*- coding: utf-8 -*-
"""E5 — evidence-restored re-queue (R1-3 / R1-10).

Same b = 3 budget, same 60-round horizon. During the withholding window the
adversary removes openings from two clients, so their updates cannot be verified
and are rejected. Once evidence is restored (round 41), the requeue arms pull
those still-unverified clients back into BOTH the local-training set and the
audit slots, with a bounded retry budget of 2. An update is never accepted
before a PASS; after 2 inconclusive retries the client is censored (dropped).

Arms: neutral, separated, adaptive (controls) and neutral_requeue / separated_requeue.
Scenarios: mixed_recovery, withholding_recovery. 20 matched seeds each.
"""
from __future__ import annotations
import argparse, hashlib, json, os, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

for _n in ("OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "OMP_NUM_THREADS"):
    os.environ[_n] = "1"
sys.path.insert(0, r".")
import numpy as np
from experiments.pba_v3 import flcore
from experiments.pba_v3 import v6_bridge as B
from experiments.pba_v3.repository import Keys
from experiments.pba_v3.v5_common import Scheduler, bootstrap, file_hash, write_json
from experiments.pba_v3.v5_response import reject_round, next_model, published_aggregate, build_training_fixture
from experiments.pba_v3.run_c_consequence import DROPPED_CLIENTS
from experiments.pba_v3.verify import PASS, INCONCLUSIVE

SCENARIOS = ("mixed_recovery", "withholding_recovery")
ARMS = ("neutral", "separated", "adaptive", "neutral_requeue", "separated_requeue")
MAX_RETRIES = 2


def run_cell(scenario, method, seed, data, rounds=60, selected=10, hidden=32, lr=.03,
             attack_start=20, attack_end=60, missing_start=20, missing_end=40):
    if scenario not in SCENARIOS or method not in ARMS:
        raise ValueError((scenario, method))
    base_method = method.replace("_requeue", "")
    requeue = method.endswith("_requeue")
    z, clients = data
    Xtr, ytr = z["X_train"], z["y_train"]
    Xte, yte = z["X_test"], z["y_test"]
    client_count = len(clients)
    rng = np.random.default_rng(seed)
    dimension = Xtr.shape[1]
    w = np.concatenate([rng.normal(0, .05, dimension * hidden), np.zeros(hidden),
                        rng.normal(0, .05, hidden), np.zeros(1)])
    initial_hash = hashlib.sha256(w.tobytes()).hexdigest()
    counts_all = [len(b) for b in clients]
    class_weights = {l: len(ytr) / (2 * max(1, int((ytr == l).sum()))) for l in (0, 1)}
    withholding_ids = B.withholding_slots(seed, client_count)
    scheduler = Scheduler(base_method, clients=client_count)
    keys = Keys.generate(list(range(client_count)))
    budget = 3
    history, round_rows, schedule = [], [], []
    pending = {}
    stat = dict(requeued=0, success=0, failed=0, censored=0, slots_forced=0, pending_end=0)
    totals = dict(attack_rounds=0, attacked_updates_applied=0, prevented_bad_rounds=0,
                  rejected_rounds=0, honest_rounds_rejected=0, audit_requests=0,
                  audit_missing_requests=0, audit_total_bytes=0, audit_cpu_ms=0.0,
                  local_training_steps=0, discarded_training_steps=0,
                  records_processed=0, updates_processed=0)
    for r in range(rounds):
        before = hashlib.sha256(w.tobytes()).hexdigest()
        chosen = sorted(map(int, rng.choice(client_count, selected, replace=False)))
        if requeue and r >= missing_end and pending:
            cand = [c for c in pending if c not in chosen][:MAX_RETRIES]
            free = [c for c in chosen if c not in DROPPED_CLIENTS and c not in pending]
            for c in cand[:min(len(free), len(cand))]:
                chosen.remove(free.pop()); chosen.append(c)
                stat["requeued"] += 1
            chosen = sorted(chosen)
        schedule.append(chosen)
        vectors, counts = [], []
        for cid in chosen:
            ids = np.asarray(clients[cid], dtype=int)
            local_rng = np.random.default_rng(np.random.SeedSequence([seed, r, cid, 71]))
            vectors.append(flcore.local_update(w, Xtr[ids], ytr[ids], hidden, local_rng, lr=lr,
                                              class_weights=class_weights))
            counts.append(counts_all[cid])
        totals["local_training_steps"] += len(chosen)
        active = scenario == "mixed_recovery" and attack_start <= r < attack_end
        aggregate = published_aggregate(vectors, counts, chosen, active)
        unavailable = withholding_ids if missing_start <= r < missing_end else []
        f = build_training_fixture(w, vectors, counts, chosen, client_count, seed, r + 1, keys, active, aggregate)
        withheld_objects = B.withhold(f, unavailable)
        slots = list(scheduler.choose(seed, r + 1, budget))
        if requeue and r >= missing_end and pending:
            for fc in [c for c in pending if c in chosen and c not in slots][:MAX_RETRIES]:
                drop = next((s for s in slots if s not in pending), None)
                if drop is None:
                    break
                slots.remove(drop); slots.append(fc); stat["slots_forced"] += 1
        slots = sorted(map(int, slots))
        res = B.audit(f.source, f.trust, slots=slots, full=False)
        scheduler.observe(res.record_outcomes)
        outcome = res.outcome
        totals["audit_requests"] += len(res.requests)
        totals["audit_total_bytes"] += res.total_network_bytes
        totals["audit_cpu_ms"] += res.cpu_ms
        totals["records_processed"] += res.records_processed
        totals["updates_processed"] += res.updates_processed
        if requeue and r < missing_end:
            for c in set(chosen) & set(unavailable):
                pending.setdefault(c, 0)
        # bounded retry bookkeeping only after evidence restoration
        for c in (list(pending) if (requeue and r >= missing_end) else []):
            if c in chosen and c in slots:
                o = res.record_outcomes.get(c)
                if o == PASS:
                    pending.pop(c); stat["success"] += 1
                elif o == INCONCLUSIVE:
                    pending[c] += 1
                    if pending[c] >= MAX_RETRIES:
                        pending.pop(c); stat["censored"] += 1
                elif o and str(o).startswith("FAIL_"):
                    pending.pop(c); stat["failed"] += 1
        rejected = reject_round(outcome)
        w = next_model(w, aggregate, outcome)
        targets = sorted(set(chosen) & set(DROPPED_CLIENTS)) if active else []
        attacked = bool(targets)
        totals["attack_rounds"] += int(attacked)
        totals["attacked_updates_applied"] += int(attacked and not rejected)
        totals["prevented_bad_rounds"] += int(attacked and rejected)
        totals["rejected_rounds"] += int(rejected)
        totals["honest_rounds_rejected"] += int(not attacked and rejected)
        totals["discarded_training_steps"] += len(chosen) if rejected else 0
        totals["audit_missing_requests"] += sum(x.startswith("missing:") for x in res.inconclusive_reason)
        round_rows.append(dict(round=r + 1, chosen=chosen, attack_targets=targets,
                               previous_model_sha256=before,
                               applied_model_sha256=hashlib.sha256(w.tobytes()).hexdigest(),
                               audit_slots=slots, outcome=outcome,
                               record_outcomes={str(k): v for k, v in res.record_outcomes.items()},
                               rejected=rejected, audit_bytes=res.total_network_bytes,
                               audit_requests=len(res.requests),
                               missing_requests=sum(x.startswith("missing:") for x in res.inconclusive_reason),
                               trained_rows=0, local_steps=len(chosen),
                               withholding_slots=list(unavailable), withheld_objects=withheld_objects))
        if r % 10 == 9 or r == rounds - 1:
            history.append(dict(round=r + 1, **flcore.metrics(yte, (flcore.predict(w, Xte, hidden) >= .5).astype(int))))
    stat["pending_end"] = len(pending)
    bridge = B.trace_metrics(round_rows)
    bridge.update({k: stat[k] for k in stat})
    return dict(scenario=scenario, method=method, seed=int(seed), rounds=rounds,
                bridge=bridge, final={k: v for k, v in history[-1].items() if k != "round"},
                trajectory=history, totals=totals, round_rows=round_rows,
                initial_model_sha256=initial_hash,
                final_model_sha256=hashlib.sha256(w.tobytes()).hexdigest(),
                selection_schedule_sha256=hashlib.sha256(json.dumps(schedule).encode()).hexdigest(),
                clients=client_count)


def _job(job):
    scenario, method, seed, data_dir, rounds = job
    if data_dir not in B._DATA_CACHE:
        B._DATA_CACHE[data_dir] = B.load(data_dir)
    return run_cell(scenario, method, seed, B._DATA_CACHE[data_dir], rounds=rounds)


def analyze(rows, seeds):
    means, paired = {}, {}
    groups = {}
    for s in SCENARIOS:
        for m in ARMS:
            g = sorted([r for r in rows if r["scenario"] == s and r["method"] == m], key=lambda x: x["seed"])
            assert [r["seed"] for r in g] == seeds, (s, m, len(g))
            groups[s, m] = g
            means[f"{s}/{m}"] = {
                **{k: bootstrap([r["bridge"][k] for r in g]) for k in
                   ("applied_violating_rounds", "prevented_violating_rounds", "compliant_rounds_retained",
                    "discarded_steps_fraction", "discarded_compliant_steps",
                    "requeued", "success", "failed", "censored", "slots_forced", "pending_end")},
                "f1": bootstrap([r["final"]["f1"] for r in g]),
                "audit_bytes": bootstrap([r["totals"]["audit_total_bytes"] for r in g]),
                "discarded_training_steps": bootstrap([r["totals"]["discarded_training_steps"] for r in g])}
            delays = [r["bridge"]["post_restore_first_apply_delay"] for r in g
                      if not r["bridge"]["post_restore_apply_censored"]]
            means[f"{s}/{m}"]["post_restore_first_apply_delay"] = {
                "conditional_mean": float(np.mean(delays)) if delays else None,
                "observed": len(delays), "censored": len(g) - len(delays), "window_rounds": 20}
    for s in SCENARIOS:
        for left, right in (("neutral_requeue", "neutral"), ("separated_requeue", "separated")):
            a, b = groups[s, left], groups[s, right]
            paired[f"{s}/{left}-{right}"] = {
                k: bootstrap([x["bridge"][k] - y["bridge"][k] for x, y in zip(a, b)])
                for k in ("applied_violating_rounds", "compliant_rounds_retained", "discarded_steps_fraction",
                          "discarded_compliant_steps")}
            paired[f"{s}/{left}-{right}"]["f1"] = bootstrap([x["final"]["f1"] - y["final"]["f1"] for x, y in zip(a, b)])
    return dict(n_runs=len(rows), means=means, paired=paired)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path(r".\experiments\e5_requeue\results"))
    ap.add_argument("--data-dir", type=Path, default=Path(r".\data\unsw_official_subset_v3"))
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--seed-start", type=int, default=320001)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--rounds", type=int, default=60)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    cfg = {k: str(v) for k, v in vars(a).items()}
    cfg.update(scenarios=list(SCENARIOS), arms=list(ARMS), budget=3, max_retries=MAX_RETRIES,
               restoration_round=41, numpy=np.__version__,
               source_sha256={str(p): file_hash(p) for p in [Path(__file__),
                   Path(r".\experiments\pba_v3\v6_bridge.py")]})
    write_json(a.out / "config.json", cfg)
    jobs = [(s, m, seed, str(a.data_dir.resolve()), a.rounds) for seed in range(a.seed_start, a.seed_start + a.seeds)
            for s in SCENARIOS for m in ARMS]
    started = time.perf_counter()
    rows = []
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(_job, j) for j in jobs]
        for done, fu in enumerate(as_completed(futs), 1):
            rows.append(fu.result())
            if done % 20 == 0 or done == len(jobs):
                print(f'{{"done":{done},"total":{len(jobs)},"elapsed":{round(time.perf_counter()-started,1)}}}', flush=True)
    with (a.out / "rows.jsonl").open("w", encoding="utf8") as fh:
        for r in rows:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")
    summary = analyze(rows, list(range(a.seed_start, a.seed_start + a.seeds)))
    summary.update({"seeds": a.seeds, "seed_start": a.seed_start, "arms": list(ARMS)})
    write_json(a.out / "summary.json", summary)
    write_json(a.out / "COMPLETE.json", {"completed": len(rows), "expected": len(jobs)})
    for s in SCENARIOS:
        print("--", s)
        for m in ARMS:
            v = summary["means"][f"{s}/{m}"]
            print(f"  {m:<18} applied={v['applied_violating_rounds']['mean']:.3f} "
                  f"compliant_rej={v['compliant_rounds_retained']['mean']:.1f} "
                  f"discard={v['discarded_steps_fraction']['mean']:.3f} f1={v['f1']['mean']:.4f} "
                  f"requeued={v['requeued']['mean']:.1f} success={v['success']['mean']:.1f} "
                  f"censored={v['censored']['mean']:.1f}")


if __name__ == "__main__":
    main()