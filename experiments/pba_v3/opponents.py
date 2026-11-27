"""Opponent models for budgeted evidence auditing.

Visibility contract (this is the paper's honesty boundary):

* ``place()`` chooses which slots to corrupt and NEVER receives the current
  round's challenge set. It may use the history of previously observed
  outcomes, which a real server also observes (it sees every evidence
  request that names one of its records).
* ``respond()`` decides, at evidence-serving time, whether a corrupted slot
  yields a failing record or an unavailable opening. This is physically
  realisable: withholding an opening needs no foresight, only refusal.

A ``reactive`` opponent therefore models feedback poisoning, not future
knowledge. The vulnerability it exploits is that an availability outcome is
silently converted into an integrity signal by the auditor's own scheduler.
"""
from dataclasses import dataclass, field

from experiments.pba_v3.config import ATTACK_ONSET_ROUND


@dataclass
class History:
    """What the server can observe: which slots were sampled, and what the
    verifier returned. The server never sees the risk-score vector itself."""
    rounds: list = field(default_factory=list)

    def add(self, round_id, slots, outcome):
        self.rounds.append({"round": round_id, "slots": tuple(slots), "outcome": outcome})

    def last(self):
        return self.rounds[-1] if self.rounds else None

    def recently_failed(self, slot, window=3):
        recent = self.rounds[-window:]
        return any(slot in r["slots"] and r["outcome"].startswith("FAIL") for r in recent)


class Opponent:
    name = "base"

    def place(self, round_id, clients, rng, history, workload):
        raise NotImplementedError

    def respond(self, corrupted, slots, rng):
        """Return (failure_slots, withhold_slots) for this round."""
        return set(corrupted), set()


class Honest(Opponent):
    name = "honest"

    def place(self, round_id, clients, rng, history, workload):
        return set()


class Persistent(Opponent):
    """Fixed targets from round 8 onwards; the classic workload."""
    name = "persistent"

    def place(self, round_id, clients, rng, history, workload):
        """``workload`` selects the placement regime, so the trace is drawn
        exactly once per round and is reproducible from the seed."""
        if workload == "withholding":
            return {0, 1} if round_id >= ATTACK_ONSET_ROUND else set()
        if workload == "random":
            return set(map(int, rng.choice(clients, 2, replace=False))) if rng.random() < .35 else set()
        return {0, 1} if round_id >= ATTACK_ONSET_ROUND else set()


class Copycat(Opponent):
    """Fail once, then migrate to a slot the auditor has not recently sampled.

    This is the competitor the audit game has to survive: it converts every
    observed detection into a relocation, so the auditor's risk scores never
    converge on the actor.
    """
    name = "copycat"

    def __init__(self):
        self.target = 0
        self.failed_once = False

    def place(self, round_id, clients, rng, history, workload):
        if round_id < 8:
            return set()
        if self.failed_once:
            sampled = set()
            for r in history.rounds[-4:]:
                sampled.update(r["slots"])
            free = [c for c in range(clients) if c not in sampled]
            if free:
                self.target = int(rng.choice(free))
            self.failed_once = False
        return {self.target}


class Withhold(Opponent):
    """Corrupt two slots and always drop the opening when sampled."""
    name = "withhold"

    def place(self, round_id, clients, rng, history, workload):
        if workload == "random":
            return set(map(int, rng.choice(clients, 2, replace=False))) if rng.random() < .35 else set()
        return {0, 1} if round_id >= ATTACK_ONSET_ROUND else set()

    def respond(self, corrupted, slots, rng):
        return set(), set(corrupted)


class WithholdSmart(Opponent):
    """Corrupt two slots, but withhold only half the time, alternating.

    A noisy availability signal is harder for a feedback scheduler to
    exploit than a deterministic one, so this opponent tests whether the
    auditor's vulnerability is specifically about *detectable* withholding.
    """
    name = "withhold_smart"

    def __init__(self):
        self.flip = 0

    def place(self, round_id, clients, rng, history, workload):
        return {0, 1} if round_id >= ATTACK_ONSET_ROUND else set()

    def respond(self, corrupted, slots, rng):
        self.flip += 1
        if self.flip % 2 == 0:
            return set(), set(corrupted)
        return set(corrupted), set()


class Predictive(Opponent):
    """Placeholder for the foresight opponent.

    Prediction needs the current challenge set, which by contract is not
    visible at placement time. The runner therefore fills in this opponent's
    targets after the schedule is drawn, so this class only marks the model.
    """
    name = "predictive"

    def place(self, round_id, clients, rng, history, workload):
        return set()


OPPONENTS = {
    "honest": Honest,
    "persistent": Persistent,
    "copycat": Copycat,
    "withhold": Withhold,
    "withhold_smart": WithholdSmart,
    "predictive": Predictive,
}
