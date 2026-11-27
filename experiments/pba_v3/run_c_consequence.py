"""Run C: consequence experiment.

A malicious aggregation server silently manipulates a training round. The
manipulation is built as a *self-consistent* transcript: everything the server
signs agrees with what it published, so a consistency check that does not read
the affected record cannot see it. Detection therefore depends on whether the
audit budget happens to sample the affected slot, which is the quantity the
protocol claims to trade against cost.

Attacks
  weight_inflation  one dominant client's numerator is tripled in both the
                    aggregate and its state leaf; its policy count is unchanged
  drop_client       two dominant clients are relabelled REJECTED with zero
                    numerator and excluded from the aggregate

Regimes
  no_audit  the manipulated aggregate is applied, no verifier is run
  missed    the verifier runs, but the manipulation is applied regardless
  caught    the verifier runs; if it returns FAIL_* the round is discarded,
            otherwise the manipulation is applied and counted as a miss

The three regimes share seeds, partitions, client selection and local sampling,
so the only difference is the audit's disposition of the round. ``caught`` is
therefore a real experiment rather than a copy of the no-attack baseline: it
contains rounds that were caught and rounds that were not, and the F1 it
reports is a mixture of applied and discarded manipulations.
"""
import argparse
import json
from pathlib import Path

import numpy as np

from experiments.pba_v3.codec import MAX_COORD, SCALE, decode_vector
from experiments.pba_v3 import flcore
from experiments.pba_v3.repository import Keys, make_fixture, put
from experiments.pba_v3.verify import FAIL_POLICY, FAIL_RESULT_REPLAY, FAIL_ROSTER, audit

FAILURES = (FAIL_ROSTER, FAIL_POLICY, FAIL_RESULT_REPLAY)


def load(data_dir):
    z = np.load(Path(data_dir) / "unsw_subset.npz")
    clients = json.loads((Path(data_dir) / "client_indices.json").read_text(encoding="utf8"))
    return z, clients


# The model is the released PBA/2 ReLU network (flcore), not a local
# reimplementation: a different activation would make the consequence numbers
# incomparable with the integration results already in the paper.
predict = flcore.predict
local_update = flcore.local_update
server_aggregate = flcore.server_aggregate
metrics = flcore.metrics


# Client 15 holds 1032 training rows, 96% of them attacks. Excluding it after
# the attack onset removes the dominant attack signal, which is the
# consequence an audit is supposed to prevent.
DROPPED_CLIENTS = (15, 13)


def manipulate_states(f, attack, chosen):
    """Mutate the fixture so the manipulation is visible in the evidence.

    Returns the set of slots the manipulation touches, so the caller can tell
    whether a FAIL outcome came from this round's manipulation or from an
    unrelated check. The transcript is recomputed and re-signed, so the server
    publishes a self-consistent round that only a record-level recomputation
    can contradict.
    """
    def rewrite(slot):
        state = f.obj(f"record/{slot}/state")
        put(f.source, f"record/{slot}/state", state)
        return state

    if attack == "weight_inflation":
        target = DROPPED_CLIENTS[0]
        if target not in chosen:
            return set()
        state = f.obj(f"record/{target}/state")
        # The aggregate and the state agree; only the declared policy count
        # does not, which is exactly the inconsistency a policy check finds.
        #
        # NOTE: this attack is NOT harmful to the model. Client 15 carries 96%
        # attack-class rows, so up-weighting it raises attack recall and F1.
        # It is kept for protocol testing only and excluded from the consequence
        # defaults; see REVISION_LOG_V4.md for the measured sign.
        state["numerator"] = state["numerator"] * 3
        put(f.source, f"record/{target}/state", state)
        denominator = sum(f.obj(f"record/{i}/state")["numerator"] for i in range(f.k))
        f.commit(denominator=denominator, recompute=True)
        return {target}

    if attack == "drop_client":
        targets = set()
        for target in DROPPED_CLIENTS:
            if target not in chosen:
                continue
            state = f.obj(f"record/{target}/state")
            # Silently reclassify as rejected with zero weight. Roster and
            # state roots are rebuilt by commit(), so every proof still holds
            # against what the server published.
            state["status"] = "REJECTED"
            state["numerator"] = 0
            state["policy_count"] = 0
            put(f.source, f"record/{target}/state", state)
            targets.add(target)
        if not targets:
            return set()
        denominator = sum(f.obj(f"record/{i}/state")["numerator"] for i in range(f.k))
        if denominator <= 0:
            return set()
        f.commit(denominator=denominator, recompute=True)
        return targets

    raise ValueError(attack)


def run_regime(regime, attack, seed, data, clients, rounds=60, selected=10, hidden=32, lr=.03,
               attack_start=20, attack_end=60, audit_budget=3):
    z, cidx = data
    Xtr, ytr = z["X_train"], z["y_train"]
    Xte, yte = z["X_test"], z["y_test"]
    rng = np.random.default_rng(seed)
    # Audit slot sampling must not consume the training RNG: sharing a stream
    # would let the regime change the client schedule, so the three regimes
    # would no longer be matched runs of the same experiment.
    audit_rng = np.random.default_rng(seed + 524287)
    # Initialisation and the float accumulator follow the released PBA/2 run
    # exactly (std 0.05, zero biases, w += aggregate / SCALE). Deviating here
    # changes the F1 ceiling and makes the consequence numbers incomparable.
    d = Xtr.shape[1]
    initial = np.concatenate([rng.normal(0, .05, d * hidden), np.zeros(hidden),
                              rng.normal(0, .05, hidden), np.zeros(1)])
    w = initial.copy()
    counts_all = [len(block) for block in cidx]
    cw = {0: len(ytr) / (2 * max(1, int((ytr == 0).sum()))),
          1: len(ytr) / (2 * max(1, int((ytr == 1).sum())))}

    history = []
    audit_outcomes = []
    attack_rounds = 0
    detected_rounds = 0
    all_ids = list(range(len(clients)))
    keys = Keys.generate(all_ids)

    for r in range(rounds):
        chosen = sorted(map(int, rng.choice(len(clients), selected, replace=False)))
        vecs, counts = [], []
        for ci in chosen:
            ids = np.asarray(cidx[ci], dtype=int)
            local_rng = np.random.default_rng(np.random.SeedSequence([seed, r, ci, 71]))
            vecs.append(local_update(w, Xtr[ids], ytr[ids], hidden, local_rng,
                                     lr=lr, class_weights=cw))
            counts.append(int(counts_all[ci]))

        in_window = attack != "none" and attack_start <= r < attack_end
        if not in_window:
            w = w + server_aggregate(vecs, counts) / SCALE
            if r % 10 == 9:
                history.append(metrics(yte, (predict(w, Xte, hidden) >= .5).astype(int)))
            continue

        # Build the transcript the server actually publishes. The manipulation
        # is applied inside the fixture and the result is recomputed from the
        # mutated states, so the transcript stays internally consistent and the
        # model receives exactly what the evidence says it received.
        params = len(initial)
        counts_all_local = [0] * len(clients)
        updates_all = [[0] * params for _ in range(len(clients))]
        for ci, vec, c in zip(chosen, vecs, counts):
            counts_all_local[ci] = int(c)
            updates_all[ci] = vec.tolist()
        f = make_fixture(round_id=r + 1, dimension=params, roster_ids=all_ids,
                         clients=len(clients), counts=counts_all_local,
                         updates=updates_all, absent_slots=set(all_ids) - set(chosen),
                         keys=keys, seed=seed * 1000 + r)

        targets = manipulate_states(f, attack, chosen)
        if targets:
            attack_rounds += 1
        # decode_vector returns a plain list; convert before the float update.
        agg = np.asarray(decode_vector(f.source["result"], params), dtype=np.int64)

        outcome = None
        if regime in ("missed", "caught"):
            slots = sorted(map(int, audit_rng.choice(len(clients), audit_budget, replace=False)))
            res = audit(f.source, f.trust, slots=slots)
            outcome = res.outcome
            audit_outcomes.append(outcome)

        discard = regime == "caught" and outcome in FAILURES and bool(targets)
        if discard:
            detected_rounds += 1
            # A caught round is replaced by the aggregate the honest execution
            # would have produced. Dropping the round outright would penalise
            # the auditor for the server's behaviour and would make the
            # comparison measure audit frequency instead of audit value.
            w = w + server_aggregate(vecs, counts) / SCALE
        else:
            w = w + agg / SCALE
        if r % 10 == 9:
            history.append(metrics(yte, (predict(w, Xte, hidden) >= .5).astype(int)))

    final_pred = (predict(w, Xte, hidden) >= .5).astype(int)
    return {"regime": regime, "attack": attack, "seed": seed,
            "attack_rounds": attack_rounds,
            "detections": detected_rounds,
            "detection_rate": detected_rounds / attack_rounds if attack_rounds else 0.0,
            "audit_calls": len(audit_outcomes),
            "audit_outcomes": audit_outcomes,
            "final": metrics(yte, final_pred), "trajectory": history}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", type=Path, default=Path("data/unsw_official_subset_v3"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seeds", nargs="*", type=int, default=[101, 102, 103])
    p.add_argument("--attacks", nargs="*", default=["none", "drop_client"])
    p.add_argument("--rounds", type=int, default=60)
    p.add_argument("--hidden", type=int, default=32)
    p.add_argument("--audit-budget", type=int, default=3)
    a = p.parse_args()

    data = load(a.data_dir)
    rows = []
    for attack in a.attacks:
        regimes = ["no_audit"] if attack == "none" else ["no_audit", "missed", "caught"]
        for regime in regimes:
            for seed in a.seeds:
                r = run_regime(regime, attack, seed, data, data[1], rounds=a.rounds,
                               hidden=a.hidden, audit_budget=a.audit_budget)
                rows.append(r)
                print(json.dumps({"attack": attack, "regime": regime, "seed": seed,
                                  "f1": round(r["final"]["f1"], 4),
                                  "detection_rate": round(r["detection_rate"], 4)}), flush=True)

    summary = {}
    for attack in a.attacks:
        for regime in {r["regime"] for r in rows if r["attack"] == attack}:
            part = [r for r in rows if r["attack"] == attack and r["regime"] == regime]
            summary[f"{attack}/{regime}"] = {
                "n": len(part),
                "f1": float(np.mean([r["final"]["f1"] for r in part])),
                "f1_sd": float(np.std([r["final"]["f1"] for r in part], ddof=1)) if len(part) > 1 else 0.0,
                "balanced_accuracy": float(np.mean([r["final"]["balanced_accuracy"] for r in part])),
                "detection_rate": float(np.mean([r["detection_rate"] for r in part])),
                "attack_rounds": float(np.mean([r["attack_rounds"] for r in part])),
                "audit_sampled_slot_hit_any": float(np.mean(
                    [any(o.startswith("FAIL") for o in r["audit_outcomes"]) for r in part]))
                if part and part[0]["audit_outcomes"] else 0.0,
            }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
