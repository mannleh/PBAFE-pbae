"""Auditor reads a bounded key interface, never a whole untrusted bundle.
PASS scope is explicit. A spot audit cannot check a global count denominator.
Peak memory is Python traced allocation, not operating-system maximum sampled post-audit RSS.
"""
import json
import time
import tracemalloc
from dataclasses import dataclass, field
from cryptography.exceptions import InvalidSignature
from .codec import (VERSION, MAX_CLIENTS, MAX_COUNT, MAX_COORD, canon, digest,
                    verify, leaf, check_proof, decode_vector, encode_vector, replay)

PASS = "PASS"
FAIL_ROSTER = "FAIL_ROSTER"
FAIL_POLICY = "FAIL_POLICY"
FAIL_RESULT_REPLAY = "FAIL_RESULT_REPLAY"
INCONCLUSIVE = "INCONCLUSIVE_EVIDENCE"
BYTE_FIELDS = ("bulletin_bytes_read", "snapshot_bytes_read", "policy_bytes_read",
               "roster_bytes_read", "state_bytes_read", "receipt_bytes_read",
               "merkle_proof_bytes_read", "opening_bytes_read", "update_bytes_read",
               "result_bytes_read", "disposition_bytes_read")


@dataclass(frozen=True)
class Trust:
    """External inputs. NEVER load these keys/pins from the evidence repository.

    ``snapshot_pin`` is the auditor's stable pre-audit pin for the signed
    post-round snapshot. In a deployment it must be obtained from an immutable
    anchor, append-only log, or authenticated capture before the mutable
    evidence repository can replace the snapshot or its openings. The test
    harness supplies this value as an explicit trust input; it is not treated
    as an endorsement by the aggregation server.
    """
    selection_key: object
    server_key: object
    registry: dict
    round_id: int
    model_hash: str
    bulletin_pin: str
    snapshot_pin: str


@dataclass
class Result:
    outcome: str = PASS
    scope: str = "sampled-records"
    policy_bound: bool = True
    aggregate_verified: bool = False
    replay_performed: bool = False
    roster_verified: bool = False
    global_normalization_checked: bool = False
    records_processed: int = 0
    updates_processed: int = 0
    cpu_ms: float = 0.0
    wall_ms: float = 0.0
    peak_memory_bytes: int = 0
    inconclusive_reason: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    bytes: dict = field(default_factory=lambda: {k: 0 for k in BYTE_FIELDS})
    request_bytes: int = 0
    response_framing_bytes: int = 0
    total_network_bytes: int = 0
    requests: list = field(default_factory=list)
    record_outcomes: dict = field(default_factory=dict)

    def as_dict(self):
        from dataclasses import asdict
        obj = asdict(self)
        obj.update(obj.pop("bytes"))
        return obj


class Fault(Exception):
    def __init__(self, outcome, reason):
        self.outcome, self.reason = outcome, reason


class Reader:
    def __init__(self, source, result):
        self.source, self.result = source, result

    def raw(self, name, category):
        # Exact bytes of the defined one-request/one-response application framing.
        request = canon({"get": name})
        self.result.request_bytes += 4 + len(request)
        self.result.requests.append(name)
        raw = self.source.get(name)
        self.result.response_framing_bytes += 5  # uint32 length + uint8 present
        if raw is None:
            raise Fault(INCONCLUSIVE, "missing:" + name)
        self.result.bytes[category] += len(raw)
        return raw

    def obj(self, name, category):
        raw = self.raw(name, category)
        try:
            obj = json.loads(raw)
            if canon(obj) != raw:
                raise ValueError("noncanonical JSON")
            return obj
        except (ValueError, UnicodeError, TypeError):
            raise Fault(FAIL_ROSTER, "malformed:" + name)


def require(condition, outcome, reason):
    if not condition:
        raise Fault(outcome, reason)


def record(reader, trust, bulletin, snapshot, policy, slot, bound, result):
    prefix = "record/" + str(slot) + "/"
    roster = reader.obj(prefix + "roster", "roster_bytes_read")
    rp = reader.obj(prefix + "roster_proof", "merkle_proof_bytes_read")
    require(roster["slot"] == slot and check_proof(leaf(roster), slot, bulletin["K"], rp,
            bulletin["roster_root"]), FAIL_ROSTER, "roster membership")
    cid = roster["client_id"]
    require(type(cid) is int and cid in trust.registry, FAIL_ROSTER, "unregistered identity")
    state = reader.obj(prefix + "state", "state_bytes_read")
    sp = reader.obj(prefix + "state_proof", "merkle_proof_bytes_read")
    require(check_proof(leaf(state), slot, bulletin["K"], sp, snapshot["state_root"]),
            FAIL_ROSTER, "state membership")
    require(state["slot"] == slot and state["client_id"] == cid, FAIL_ROSTER, "slot identity")
    result.records_processed += 1
    require(state["status"] in ("ACCEPTED", "REJECTED", "TIMEOUT", "ABSENT"),
            FAIL_ROSTER, "unknown status encoding")
    numerator = state["numerator"]
    require(type(numerator) is int and 0 <= numerator <= MAX_COUNT,
            FAIL_ROSTER, "malformed weight numerator")
    if state["receipt_digest"] is None:
        # An independent close observation is necessary to support an exclusion;
        # it attests the service's observation, not physical submission truth.
        disposition = reader.obj(prefix + "disposition", "disposition_bytes_read")
        dc = verify(trust.selection_key, "PBA2/disposition", disposition)
        require(dc == {"bulletin_hash": trust.bulletin_pin, "client_id": cid,
                       "slot": slot, "status": state["status"]}, FAIL_ROSTER, "close observation")
        if bound:
            require(state["status"] in ("ABSENT", "TIMEOUT") and numerator == 0,
                    FAIL_POLICY, "exclusion rule")
        return roster, state, None
    receipt = reader.obj(prefix + "receipt", "receipt_bytes_read")
    require(digest("PBA2/receipt", canon(receipt)) == state["receipt_digest"],
            FAIL_ROSTER, "receipt digest")
    q = verify(trust.registry[cid], "PBA2/client", receipt)
    require(q["client_id"] == cid and q["round"] == trust.round_id and
            q["model_hash"] == trust.model_hash and q["bulletin_hash"] == trust.bulletin_pin and
            q["version"] == VERSION and q["status"] == "SUBMITTED",
            FAIL_ROSTER, "receipt context")
    count = q["declared_count"]
    require(type(count) is int and 0 < count <= MAX_COUNT, FAIL_ROSTER, "count domain")
    if bound:
        require(state["policy_version"] == policy["version"] and
                state["policy_count"] == count and type(state["policy_count"]) is int and
                numerator == count and state["status"] == "ACCEPTED",
                FAIL_POLICY, "local declaration/weight/status rule")
    opening = reader.raw(prefix + "opening", "opening_bytes_read")
    raw = reader.raw(prefix + "update", "update_bytes_read")
    require(len(opening) == 32 and digest("PBA2/update", raw, opening) == q["update_digest"],
            FAIL_ROSTER, "update opening")
    vector = decode_vector(raw, bulletin["dimension"])
    result.updates_processed += 1
    return roster, state, vector


def audit(source, trust, slots=(), full=False, bound=True):
    result = Result(scope="full-round" if full else "sampled-records", policy_bound=bound)
    reader = Reader(source, result)
    cpu = time.process_time_ns()
    wall = time.perf_counter_ns()
    own_trace = not tracemalloc.is_tracing()
    if own_trace:
        tracemalloc.start()
    baseline_mem = tracemalloc.get_traced_memory()[0]
    tracemalloc.reset_peak()
    try:
        b = reader.obj("bulletin", "bulletin_bytes_read")
        require(digest("PBA2/bulletin", canon(b)) == trust.bulletin_pin, FAIL_ROSTER, "bulletin pin")
        bulletin = verify(trust.selection_key, "PBA2/selection", b)
        require(bulletin["round"] == trust.round_id and bulletin["model_hash"] == trust.model_hash
                and bulletin["version"] == VERSION and type(bulletin["K"]) is int
                and 0 < bulletin["K"] <= MAX_CLIENTS and type(bulletin["dimension"]) is int
                and 0 < bulletin["dimension"] <= 10**6, FAIL_ROSTER, "bulletin context/domain")
        s = reader.obj("snapshot", "snapshot_bytes_read")
        require(digest("PBA2/snapshot", canon(s)) == trust.snapshot_pin, FAIL_ROSTER, "snapshot pin")
        snapshot = verify(trust.server_key, "PBA2/server", s)
        require(snapshot["bulletin_hash"] == trust.bulletin_pin and snapshot["K"] == bulletin["K"],
                FAIL_ROSTER, "snapshot context/length")
        denominator = snapshot["denominator"]
        require(type(denominator) is int and 0 < denominator <= MAX_CLIENTS * MAX_COUNT,
                FAIL_ROSTER, "denominator domain")
        policy = reader.obj("policy", "policy_bytes_read")
        require(digest("PBA2/policy", canon(policy)) == bulletin["policy_hash"], FAIL_ROSTER, "policy digest")
        if bound:
            require(policy == {"version": "declared-fedavg-v2", "max_count": MAX_COUNT,
                               "status_rule": "valid-submissions-accepted;independent-close-for-absence"},
                    FAIL_POLICY, "unsupported policy")
        chosen = list(range(bulletin["K"])) if full else list(slots)
        require(len(chosen) == len(set(chosen)) and all(type(x) is int and 0 <= x < bulletin["K"]
                for x in chosen), FAIL_ROSTER, "invalid audit selection")
        roster_leaves, state_leaves, client_ids, vectors, nums = [], [], [], [], []
        for slot in chosen:
            try:
                roster, state, vector = record(reader, trust, bulletin, snapshot, policy, slot, bound, result)
                result.record_outcomes[slot] = PASS
                if full:
                    roster_leaves.append(leaf(roster))
                    state_leaves.append(leaf(state))
                    client_ids.append(roster["client_id"])
                    if state["status"] == "ACCEPTED":
                        require(vector is not None, FAIL_POLICY, "accepted update absent")
                        vectors.append(vector)
                        nums.append(state["numerator"])
            except (Fault, InvalidSignature, ValueError, KeyError, TypeError, OverflowError) as e:
                f = e if isinstance(e, Fault) else Fault(FAIL_ROSTER, "malformed or unauthenticated record")
                result.record_outcomes[slot] = f.outcome
                result.findings.append({"slot": slot, "outcome": f.outcome, "reason": f.reason})
        if full and not result.findings:
            from .codec import Tree
            require(len(set(client_ids)) == bulletin["K"] and
                    Tree(roster_leaves).root == bulletin["roster_root"] and
                    Tree(state_leaves).root == snapshot["state_root"], FAIL_ROSTER, "full set mismatch")
            result.roster_verified = True
            if bound:
                result.global_normalization_checked = True
                require(sum(nums) == denominator and bool(nums), FAIL_POLICY, "global normalization")
            raw_result = reader.raw("result", "result_bytes_read")
            require(digest("PBA2/result", raw_result) == snapshot["result_digest"],
                    FAIL_RESULT_REPLAY, "result commitment")
            decode_vector(raw_result, bulletin["dimension"])
            expected = encode_vector(replay(vectors, nums, denominator))
            result.replay_performed = True
            require(raw_result == expected, FAIL_RESULT_REPLAY, "replay mismatch")
            result.aggregate_verified = True
    except (Fault, InvalidSignature, ValueError, KeyError, TypeError, OverflowError) as e:
        f = e if isinstance(e, Fault) else Fault(FAIL_ROSTER, "malformed or unauthenticated public object")
        result.findings.append({"slot": None, "outcome": f.outcome, "reason": f.reason})
    finally:
        # Known contradiction takes precedence over missing evidence, all findings retained.
        result.inconclusive_reason = [x["reason"] for x in result.findings if x["outcome"] == INCONCLUSIVE]
        for outcome in (FAIL_ROSTER, FAIL_POLICY, FAIL_RESULT_REPLAY, INCONCLUSIVE):
            if any(x["outcome"] == outcome for x in result.findings):
                result.outcome = outcome
                result.aggregate_verified = False
                break
        result.total_network_bytes = sum(result.bytes.values()) + result.request_bytes + result.response_framing_bytes
        result.peak_memory_bytes = max(0, tracemalloc.get_traced_memory()[1] - baseline_mem)
        if own_trace:
            tracemalloc.stop()
        result.cpu_ms = (time.process_time_ns() - cpu) / 1_000_000
        result.wall_ms = (time.perf_counter_ns() - wall) / 1_000_000
    return result


# --- PBA/3: segment-sum audit tier ----------------------------------------

def audit_segment(source, trust, seed_hex, budget_segments, segments=None, bound=True):
    """Sample segments, rebuild each from record-level contributions, and
    compare against the published segment sums.

    Reads: bulletin, snapshot, policy, and for every sampled segment the
    per-record contribution plus its proof. Does not read receipts, state
    leaves, openings, or the published result. ``aggregate_verified`` stays
    false: the tier contradicts a published sum, it does not certify one.
    """
    from experiments.pba_v3.codec import (canon, check_proof, derive_challenge_seed,
                                          digest, leaf, sealed_sample, decode_vector)
    result = Result(scope="sampled-segments", policy_bound=bound)
    reader = Reader(source, result)
    cpu = time.process_time_ns()
    wall = time.perf_counter_ns()
    try:
        b = reader.obj("bulletin", "bulletin_bytes_read")
        if digest("PBA2/bulletin", canon(b)) != trust.bulletin_pin:
            raise Fault(FAIL_ROSTER, "bulletin pin")
        bulletin = verify(trust.selection_key, "PBA2/selection", b)
        s = reader.obj("snapshot", "snapshot_bytes_read")
        if digest("PBA2/snapshot", canon(s)) != trust.snapshot_pin:
            raise Fault(FAIL_ROSTER, "snapshot pin")
        snapshot = verify(trust.server_key, "PBA2/server", s)
        n_seg = segments or snapshot.get("segment_count")
        if not n_seg or snapshot.get("segment_root") is None:
            raise Fault(INCONCLUSIVE, "segment commitments absent")
        accepted = snapshot["accepted"]
        chosen = sealed_sample(seed_hex, [1.0] * n_seg, min(budget_segments, n_seg))
        result.records_processed = accepted
        result.bytes["roster_bytes_read"] = 0
        for seg in chosen:
            published = reader.obj(f"segment/{seg}", "update_bytes_read")
            rebuilt = None
            for idx in range(accepted):
                c = reader.obj(f"record/{idx}/contribution/{seg}", "update_bytes_read")
                p = reader.obj(f"segment/{seg}/proof/{idx}", "merkle_proof_bytes_read")
                if not check_proof(leaf({"segment": seg, "record": idx, "contribution": c}),
                                   seg * accepted + idx, accepted * n_seg, p,
                                   snapshot["segment_root"]):
                    raise Fault(FAIL_ROSTER, f"segment contribution proof {seg}/{idx}")
                rebuilt = list(c) if rebuilt is None else [x + y for x, y in zip(rebuilt, c)]
            if rebuilt != list(published):
                raise Fault(FAIL_RESULT_REPLAY, f"segment {seg} sum mismatch")
        result.segments_checked = len(chosen)
        result.coverage_mass = len(chosen) / n_seg
    except (Fault, InvalidSignature, ValueError, KeyError, TypeError, OverflowError) as e:
        f = e if isinstance(e, Fault) else Fault(FAIL_ROSTER, "malformed segment evidence")
        result.findings.append({"slot": None, "outcome": f.outcome, "reason": f.reason})
    finally:
        for outcome in (FAIL_ROSTER, FAIL_POLICY, FAIL_RESULT_REPLAY, INCONCLUSIVE):
            if any(x["outcome"] == outcome for x in result.findings):
                result.outcome = outcome
                break
        result.total_network_bytes = sum(result.bytes.values()) + result.request_bytes + result.response_framing_bytes
        result.cpu_ms = (time.process_time_ns() - cpu) / 1_000_000
        result.wall_ms = (time.perf_counter_ns() - wall) / 1_000_000
    return result


def audit_sealed(source, trust, budget, beacon, risk_scores, bound=True):
    """Commit-before-reveal record audit.

    The challenge set is fixed by H(bulletin, round, beacon) before the round's
    evidence is served, so the server cannot steer which slots are sampled.
    ``risk_scores`` are the weights carried over from the previous round; they
    are allowed to adapt, but the mapping to slots is sealed for this round.
    """
    from experiments.pba_v3.codec import derive_challenge_seed, sealed_sample
    seed = derive_challenge_seed(trust.bulletin_pin, trust.round_id, beacon)
    slots = sealed_sample(seed, risk_scores, budget)
    return audit(source, trust, slots=slots, bound=bound)
