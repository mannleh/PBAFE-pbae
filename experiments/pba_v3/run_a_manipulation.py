"""Run A: manipulation of feedback-driven audit scheduling.

Five schedules x five opponents x three workloads.

Schedule semantics
------------------
uniform            random selection, auditor-private RNG
round_robin        deterministic rotation
adaptive           v2 behaviour: FAIL +1.0, INCONCLUSIVE +0.5, PASS +0
sealed_adaptive    weighted selection whose seed is fixed by
                   H(bulletin, round, beacon) BEFORE the round is served,
                   but availability outcomes still feed risk
sealed_navail      sealed_adaptive plus the semantic rule that an
                   availability outcome is not an integrity signal

Opponent semantics
------------------
honest             no corruption
persistent         fixed targets, record tampering
copycat            fail once, then migrate to a recently unsampled slot
withhold           fixed targets, opening withheld whenever sampled
withhold_smart     as withhold, but alternating so the signal is noisy
predictive         knows the challenge set in advance; fails only if
                   sampled. Models a server that can predict the auditor's
                   sampling. Against a sealed schedule it gets no
                   prediction, which is exactly the property under test.
"""
import argparse
import json
import math
import statistics
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

from experiments.pba_v3.codec import derive_challenge_seed, sealed_sample
from experiments.pba_v3.config import ATTACK_ONSET_ROUND
from experiments.pba_v3.opponents import OPPONENTS
from experiments.pba_v3.repository import make_fixture, tamper
from experiments.pba_v3.verify import audit, FAIL_POLICY, FAIL_RESULT_REPLAY, FAIL_ROSTER, INCONCLUSIVE

FAILURES = (FAIL_ROSTER, FAIL_POLICY, FAIL_RESULT_REPLAY)
SEALED = ("sealed_adaptive", "sealed_navail")
WORKLOADS = ("persistent", "random", "withholding")


def beacon_for(seed, round_id):
    """Stand-in for an external unpredictable beacon."""
    from experiments.pba_v3.codec import digest
    return digest("PBA3/beacon", str(seed).encode(), str(round_id).encode())


def choose_slots(method, round_id, clients, budget, scores, rng, bulletin_pin, seed):
    if method == "uniform":
        return sorted(map(int, rng.choice(clients, budget, replace=False)))
    if method == "round_robin":
        return [(round_id * budget + j) % clients for j in range(budget)]
    if method in ("adaptive", "sealed_adaptive", "sealed_navail"):
        floor = max(0.05, 1.0 / clients)
        w = np.asarray(scores, dtype=float) + floor
        if method == "adaptive":
            w = w / w.sum()
            return sorted(map(int, rng.choice(clients, budget, replace=False, p=w)))
        s = derive_challenge_seed(bulletin_pin, round_id, beacon_for(seed, round_id))
        return sealed_sample(s, w, budget)
    raise ValueError(method)


def update_scores(scores, result, slots, method):
    for cid in slots:
        o = result.record_outcomes.get(cid)
        if o in FAILURES:
            scores[cid] += 1.0
        elif o == INCONCLUSIVE and method != "sealed_navail":
            scores[cid] += 0.5


def one(schedule, opponent, workload, seed, rounds=60, clients=30, budget=3, dimension=256):
    rng = np.random.default_rng(seed + 7919)
    placement_rng = np.random.default_rng(seed + 104729)
    scores = np.zeros(clients, dtype=float)
    opp = OPPONENTS[opponent]()
    history_slots = []

    # Key generation dominates per-round cost (~25 ms/client). The roster is
    # fixed for a seed, so one key set is reused across rounds; this does not
    # change any cryptographic check, only how the fixture is built.
    from experiments.pba_v3.repository import Keys
    keys = Keys.generate(list(range(clients)))

    attack_rounds = detected = covered = inconclusive = 0
    total_bytes = 0
    first_detection = None
    onset = None

    for r in range(rounds):
        round_id = r + 1
        fixture = make_fixture(round_id=round_id, dimension=dimension, clients=clients,
                               seed=seed * 1000 + r, keys=keys)
        pin = fixture.trust.bulletin_pin

        # 1) placement: never sees the challenge set, only past observations
        if opponent == "predictive":
            targets = set()
        else:
            targets = opp.place(round_id, clients, placement_rng, _Hist(history_slots), workload)

        active = bool(targets)
        if active and onset is None:
            onset = r

        # 2) challenge set
        slots = choose_slots(schedule, r, clients, budget, scores, rng, pin, seed)

        # 3) predictive opponent sees the set only if it can predict the seed.
        #    When the schedule is sealed it gets no prediction and falls back to
        #    fixed targets, so its detection rate reflects real coverage rather
        #    than a definitional zero.
        if opponent == "predictive":
            if schedule not in SEALED:
                targets = set(list(slots)[:1])
            elif round_id >= ATTACK_ONSET_ROUND:
                targets = {0}
            else:
                targets = set()
            active = bool(targets)
            if active and onset is None:
                onset = r

        # 4) server behaviour at evidence time
        withhold = False
        if workload == "withholding":
            withhold = True
        elif opponent in ("withhold",):
            withhold = True
        elif opponent == "withhold_smart":
            withhold = (r % 2 == 1)

        if active:
            attack_rounds += 1
            if withhold:
                for cid in targets:
                    fixture.source.pop(f"record/{cid}/opening", None)
            else:
                # A server that tampers and then withholds would emit a FAIL
                # instead of a detection, which is a different outcome; keep
                # record tampering and availability attacks mutually exclusive.
                fixture = tamper(fixture, "declared_count_policy", tuple(sorted(targets)))

        result = audit(fixture.source, fixture.trust, slots=slots, full=False, bound=True)
        total_bytes += result.total_network_bytes
        history_slots.append({"round": r, "slots": tuple(slots), "outcome": result.outcome})

        if result.outcome == INCONCLUSIVE:
            inconclusive += 1
        if active:
            hit = set(slots) & set(targets)
            if hit:
                covered += 1
                # A withheld opening yields FAIL_POLICY (the state check runs
                # before the opening read), so availability attacks must not be
                # scored as detections here.
                if not withhold and any(result.record_outcomes.get(c) in FAILURES for c in hit):
                    detected += 1
                    if first_detection is None:
                        first_detection = r - (onset or r)

        update_scores(scores, result, slots, schedule)

    return {
        "schedule": schedule, "opponent": opponent, "workload": workload, "seed": seed,
        "rounds": rounds, "clients": clients, "budget": budget, "dimension": dimension,
        "attack_rounds": attack_rounds,
        "tdr": detected / attack_rounds if attack_rounds else 0.0,
        "coverage": covered / attack_rounds if attack_rounds else 0.0,
        "inconclusive": inconclusive,
        "inconclusive_per_round": inconclusive / rounds,
        "bytes_read": int(total_bytes),
        "latency": first_detection,
    }


class _Hist:
    def __init__(self, rows):
        self.rounds = rows

    def last(self):
        return self.rounds[-1] if self.rounds else None


def _job(a):
    return one(*a)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seeds", type=int, default=100)
    p.add_argument("--quick", action="store_true")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--dimension", type=int, default=256)
    p.add_argument("--schedule", nargs="*", default=None)
    p.add_argument("--opponent", nargs="*", default=None)
    p.add_argument("--workload", nargs="*", default=None)
    a = p.parse_args()
    seeds = 8 if a.quick else a.seeds
    sched = a.schedule or ["uniform", "round_robin", "adaptive", "sealed_adaptive", "sealed_navail"]
    opps = a.opponent or ["honest", "persistent", "copycat", "withhold", "withhold_smart", "predictive"]
    wls = a.workload or list(WORKLOADS)

    jobs = [(s, o, w, 100000 + i, 60, 30, 3, a.dimension)
            for s in sched for o in opps for w in wls for i in range(seeds)]
    rows = []
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        for n, r in enumerate(ex.map(_job, jobs, chunksize=1), 1):
            rows.append(r)
            if n % 100 == 0:
                print(json.dumps({"done": n, "total": len(jobs)}), flush=True)

    summary = []
    for s in sched:
        for o in opps:
            for w in wls:
                part = [r for r in rows if r["schedule"] == s and r["opponent"] == o and r["workload"] == w]
                if not part:
                    continue
                def mc(k):
                    v = [r[k] for r in part]
                    m = statistics.mean(v)
                    ci = 1.96 * statistics.stdev(v) / math.sqrt(len(v)) if len(v) > 1 else 0.0
                    return round(m, 4), round(ci, 4)
                t, tc = mc("tdr")
                c, cc = mc("coverage")
                i_, i_c = mc("inconclusive")
                b, _ = mc("bytes_read")
                summary.append({"schedule": s, "opponent": o, "workload": w, "n": len(part),
                                "tdr": t, "tdr_ci": tc, "coverage": c, "coverage_ci": cc,
                                "inconclusive": i_, "inconclusive_ci": i_c, "bytes": b})

    out = {"grid": {"schedules": sched, "opponents": opps, "workloads": list(WORKLOADS),
                    "seeds": seeds, "dimension": a.dimension},
           "summary": summary, "rows": rows}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=2), encoding="utf8")
    print(json.dumps({"rows": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
