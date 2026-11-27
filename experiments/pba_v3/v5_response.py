"""Prospective, no-oracle reject-and-retain FL response experiment.

The response controller receives only the verifier outcome. It rejects FAIL or
INCONCLUSIVE rounds and retains its preceding model; it never substitutes an
honest aggregate. Ground truth is used only for post-decision evaluation.
Training/data remain the bounded released UNSW subset, not a new benchmark.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import time

# Bound BLAS thread oversubscription in process workers. Diagnostic timings are
# still machine/process specific and are not networking or scalability results.
for _name in ("OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "OMP_NUM_THREADS"):
    os.environ.setdefault(_name, "1")

import numpy as np

from . import flcore
from .codec import SCALE, decode_vector, digest, encode_vector
from .repository import Keys, make_fixture
from .run_c_consequence import DROPPED_CLIENTS, load, manipulate_states
from .verify import INCONCLUSIVE, PASS, audit

ARMS = (
    "clean_noaudit", "drop_noaudit", "drop_uniform_b3", "drop_neutral_b3",
    "drop_separated_b3", "drop_full_b30",
)
_DATA_CACHE = {}


def reject_round(outcome):
    """Controller boundary: no target identities, labels, or reference model."""
    return outcome is not None and (outcome.startswith("FAIL_") or outcome == INCONCLUSIVE)


def next_model(previous, published, outcome):
    return previous.copy() if reject_round(outcome) else previous + published / SCALE


def published_aggregate(vectors, counts, chosen, attack_active):
    """Server computation for both audited and unaudited arms.

    This is the actually published aggregate, never an honest recovery model.
    Its equivalence to the authenticated fixture's result is unit tested.
    """
    keep = [i for i, cid in enumerate(chosen)
            if not (attack_active and cid in DROPPED_CLIENTS)]
    if not keep:
        raise ValueError("all selected clients dropped: specified matrix requires survivors")
    return flcore.server_aggregate([vectors[i] for i in keep], [counts[i] for i in keep])


def build_training_fixture(w, vectors, counts, chosen, client_count, seed, round_id,
                           keys, attack_active, aggregate):
    dimension = len(w)
    all_counts = [0] * client_count
    all_updates = [[0] * dimension for _ in range(client_count)]
    for cid, vec, count in zip(chosen, vectors, counts):
        all_counts[cid] = int(count)
        all_updates[cid] = vec.tolist()
    f = make_fixture(
        round_id=round_id, dimension=dimension, clients=client_count,
        roster_ids=list(range(client_count)), counts=all_counts,
        updates=all_updates, absent_slots=set(range(client_count)) - set(chosen),
        keys=keys, seed=seed * 1000 + round_id - 1,
        model_hash=digest("PBA2/model", np.asarray(w, dtype="<f8").tobytes()),
        actual_result=encode_vector(aggregate.tolist()),
    )
    if attack_active:
        manipulate_states(f, "drop_client", chosen)
    # A release guard: this comparison uses no clean/honest aggregate.
    if not np.array_equal(decode_vector(f.source["result"], dimension), aggregate):
        raise AssertionError("published aggregate and committed fixture disagree")
    return f


def run_arm(arm, seed, data, rounds=60, selected=10, hidden=32, lr=.03,
            attack_start=20, attack_end=60, budget=None):
    if arm not in ARMS:
        raise ValueError(arm)
    from .v5_common import Scheduler
    z, clients = data
    Xtr, ytr = z["X_train"], z["y_train"]
    Xte, yte = z["X_test"], z["y_test"]
    client_count = len(clients)
    if client_count <= max(DROPPED_CLIENTS) or not 0 < selected <= client_count:
        raise ValueError("client population incompatible with fixed attack")
    rng = np.random.default_rng(seed)
    dimension = Xtr.shape[1]
    w = np.concatenate([rng.normal(0, .05, dimension * hidden), np.zeros(hidden),
                        rng.normal(0, .05, hidden), np.zeros(1)])
    initial_hash = hashlib.sha256(w.tobytes()).hexdigest()
    counts_all = [len(block) for block in clients]
    if min(counts_all) < 1:
        raise ValueError("empty training client")
    class_weights = {label: len(ytr) / (2 * max(1, int((ytr == label).sum())))
                     for label in (0, 1)}
    audited = "noaudit" not in arm
    full = arm == "drop_full_b30"
    method = "uniform" if full or not audited else arm.split("_")[1]
    scheduler = Scheduler(method, clients=client_count) if audited else None
    keys = Keys.generate(list(range(client_count))) if audited else None
    budget = client_count if full else (3 if budget is None else budget)
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
        chosen = sorted(map(int, rng.choice(client_count, selected, replace=False)))
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
        active = arm != "clean_noaudit" and attack_start <= r < attack_end
        aggregate = published_aggregate(vectors, counts, chosen, active)
        outcome, slots, record_outcomes = None, [], {}
        audit_bytes, audit_requests, missing_requests = 0, 0, 0
        if audited:
            start = time.perf_counter_ns()
            f = build_training_fixture(w, vectors, counts, chosen, client_count, seed,
                                       r + 1, keys, active, aggregate)
            totals["evidence_build_wall_ms"] += (time.perf_counter_ns() - start) / 1e6
            slots = list(range(client_count)) if full else scheduler.choose(seed, r + 1, budget)
            res = audit(f.source, f.trust, slots=slots, full=full)
            outcome, record_outcomes = res.outcome, res.record_outcomes
            scheduler.observe(record_outcomes)
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
                               trained_rows=rows_processed, local_steps=len(chosen)))
        if r % 10 == 9 or r == rounds - 1:
            history.append(dict(round=r + 1, **flcore.metrics(
                yte, (flcore.predict(w, Xte, hidden) >= .5).astype(int))))
    assert totals["attack_rounds"] == (totals["attacked_updates_applied"]
                                       + totals["prevented_bad_rounds"])
    assert totals["audit_total_bytes"] == (totals["audit_request_bytes"]
        + totals["audit_response_payload_bytes"] + totals["audit_response_framing_bytes"])
    return dict(arm=arm, seed=int(seed), rounds=rounds, audit_budget=budget if audited else 0,
                response_policy="reject FAIL/INCONCLUSIVE; retain previous model; no replacement",
                final={k: v for k, v in history[-1].items() if k != "round"},
                trajectory=history, totals=totals, round_rows=round_rows,
                initial_model_sha256=initial_hash,
                final_model_sha256=hashlib.sha256(w.tobytes()).hexdigest(),
                selection_schedule_sha256=hashlib.sha256(json.dumps(schedule).encode()).hexdigest(),
                dimension=len(w), clients=client_count, train_rows=len(ytr), test_rows=len(yte))


def _job(args):
    arm, seed, data_dir, rounds = args
    if data_dir not in _DATA_CACHE:
        _DATA_CACHE[data_dir] = load(data_dir)
    return run_arm(arm, seed, _DATA_CACHE[data_dir], rounds=rounds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data/unsw_official_subset_v3"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--seed-start", type=int, default=300001)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--rounds", type=int, default=60)
    parser.add_argument("--arms", nargs="+", choices=ARMS, default=list(ARMS))
    args = parser.parse_args()
    if args.seeds < 1 or args.workers < 1 or not 1 <= args.rounds <= 60:
        parser.error("positive seeds/workers and 1..60 rounds required")
    args.out.mkdir(parents=True, exist_ok=False)
    config = vars(args).copy()
    config.update(data_dir=str(args.data_dir.resolve()), out=str(args.out.resolve()),
                  status="RUNNING", attack_start_round=21, attack_end_round=60,
                  timing_scope="local diagnostics, not deployment/network benchmark",
                  cost_scope="payload + exact verifier application framing; no TCP/TLS")
    source_paths = [Path(__file__), Path(__file__).with_name("v5_common.py"),
                    Path(__file__).with_name("flcore.py"), Path(__file__).with_name("verify.py"),
                    Path(__file__).with_name("repository.py"), Path(__file__).with_name("run_c_consequence.py")]
    config["source_sha256"] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
    config["data_sha256"] = {name: hashlib.sha256((args.data_dir / name).read_bytes()).hexdigest()
                              for name in ("unsw_subset.npz", "client_indices.json")}
    config["numpy_version"] = np.__version__
    (args.out / "config.json").write_text(json.dumps(config, indent=2), encoding="utf8")
    jobs = [(arm, seed, str(args.data_dir.resolve()), args.rounds)
            for seed in range(args.seed_start, args.seed_start + args.seeds) for arm in args.arms]
    rows = []
    try:
        with (args.out / "rows.jsonl").open("x", encoding="utf8") as checkpoint:
            with ProcessPoolExecutor(max_workers=args.workers) as pool:
                futures = [pool.submit(_job, job) for job in jobs]
                for future in as_completed(futures):
                    row = future.result()
                    checkpoint.write(json.dumps(row, separators=(",", ":")) + "\n")
                    checkpoint.flush()
                    os.fsync(checkpoint.fileno())
                    rows.append(row)
                    print(json.dumps(dict(completed=len(rows), total=len(jobs), arm=row["arm"],
                                          seed=row["seed"], f1=row["final"]["f1"],
                                          rejected=row["totals"]["rejected_rounds"])), flush=True)
    except BaseException as exc:
        (args.out / "FAILED.json").write_text(json.dumps(dict(
            error=repr(exc), completed=len(rows), expected=len(jobs))), encoding="utf8")
        raise
    (args.out / "COMPLETE.json").write_text(json.dumps(dict(
        status="COMPLETED", completed=len(rows), expected=len(jobs))), encoding="utf8")


if __name__ == "__main__":
    main()
