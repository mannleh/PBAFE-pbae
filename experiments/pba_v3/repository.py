"""Repository-side preparation and adversarial fixtures, NOT trusted verifier code.
Round roots are fixed before sampling; only clients/selection service own their
signing keys. TestHarness keys never enter the evidence-reader interface.
"""
import json
from dataclasses import dataclass, replace
import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .codec import (VERSION, MAX_COUNT, canon, digest, encode_vector, decode_vector,
                    replay, leaf, Tree, sign)
from .verify import Trust

POLICY = {"version": "declared-fedavg-v2", "max_count": MAX_COUNT,
          "status_rule": "valid-submissions-accepted;independent-close-for-absence"}


def put(store, name, obj):
    store[name] = canon(obj)


def signed(store, name, key, domain, body):
    envelope = sign(key, domain, body)
    put(store, name, envelope)
    return envelope


@dataclass
class Keys:
    selection: object
    server: object
    clients: dict

    @classmethod
    def generate(cls, ids):
        return cls(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(),
                   {i: Ed25519PrivateKey.generate() for i in ids})


@dataclass
class Fixture:
    source: dict
    trust: Trust
    keys: Keys
    k: int
    dimension: int

    def clone(self):
        return Fixture(dict(self.source), self.trust, self.keys, self.k, self.dimension)

    def obj(self, name):
        return json.loads(self.source[name])

    def resign_receipt(self, slot):
        name = f"record/{slot}/receipt"
        body = self.obj(name)["body"]
        signed(self.source, name, self.keys.clients[body["client_id"]], "PBA2/client", body)
        self.bind_receipt(slot)

    def bind_receipt(self, slot):
        name = f"record/{slot}/state"
        state = self.obj(name)
        state["receipt_digest"] = digest("PBA2/receipt", self.source[f"record/{slot}/receipt"])
        put(self.source, name, state)

    def commit(self, denominator=None, recompute=False):
        """Malicious server can commit arbitrary states/results before sampling.
        The selection bulletin is not changed or re-signed by this operation.
        The fixture refreshes ``trust.snapshot_pin`` to model an auditor that
        captured this signed snapshot before the mutable repository is exposed.
        It is not an endorsement of correctness. A deployment must obtain the
        equivalent pin from an immutable anchor, append-only log, or
        authenticated capture; otherwise a server can re-sign a replacement
        snapshot and the verifier can only reason about the currently observed
        transcript.
        """
        states = [self.obj(f"record/{i}/state") for i in range(self.k)]
        tree = Tree([leaf(x) for x in states])
        snapshot = self.obj("snapshot")["body"]
        snapshot["state_root"] = tree.root
        if denominator is not None:
            snapshot["denominator"] = denominator
        if recompute:
            accepted = [i for i,s in enumerate(states) if s["status"] == "ACCEPTED"]
            nums = [states[i]["numerator"] for i in accepted]
            vectors = [decode_vector(self.source[f"record/{i}/update"], self.dimension) for i in accepted]
            self.source["result"] = encode_vector(replay(vectors, nums, snapshot["denominator"]))
        snapshot["result_digest"] = digest("PBA2/result", self.source["result"])
        env = signed(self.source, "snapshot", self.keys.server, "PBA2/server", snapshot)
        for i in range(self.k):
            put(self.source, f"record/{i}/state_proof", tree.proof(i))
        self.trust = replace(self.trust, snapshot_pin=digest("PBA2/snapshot", canon(env)))


def make_fixture(round_id=1, dimension=8, clients=10, seed=7, counts=None,
                 updates=None, model_hash=None, roster_ids=None, keys=None,
                 absent_slots=(), actual_result=None):
    ids = list(range(clients)) if roster_ids is None else list(roster_ids)
    k = len(ids)
    if not k or len(set(ids)) != k:
        raise ValueError("honest service must issue nonempty unique roster")
    keys = keys or Keys.generate(ids)
    rng = np.random.default_rng(seed)
    counts = list(counts) if counts is not None else rng.integers(10, 101, size=k).tolist()
    updates = list(updates) if updates is not None else rng.integers(-1000,1001,size=(k,dimension)).tolist()
    if len(counts) != k or len(updates) != k:
        raise ValueError("input length mismatch")
    model_hash = model_hash or digest("PBA2/model", str(round_id).encode())
    entries = [{"slot": i, "client_id": cid, "eligibility": "ENROLLED"} for i,cid in enumerate(ids)]
    roster_tree = Tree([leaf(x) for x in entries])
    source = {}
    bulletin = {"version": VERSION, "round": round_id, "model_hash": model_hash,
                "roster_root": roster_tree.root, "policy_hash": digest("PBA2/policy", canon(POLICY)),
                "deadline": round_id * 1000 + 900, "K": k, "dimension": dimension}
    env = signed(source, "bulletin", keys.selection, "PBA2/selection", bulletin)
    bulletin_pin = digest("PBA2/bulletin", canon(env))
    put(source, "policy", POLICY)
    states, accepted_vectors, nums = [], [], []
    for i,cid in enumerate(ids):
        prefix = f"record/{i}/"
        put(source, prefix+"roster", entries[i])
        put(source, prefix+"roster_proof", roster_tree.proof(i))
        if i in absent_slots:
            state = {"slot":i,"client_id":cid,"status":"ABSENT","numerator":0,
                     "policy_count":0,"policy_version":POLICY["version"],"receipt_digest":None}
            disposition = {"bulletin_hash":bulletin_pin,"client_id":cid,"slot":i,"status":"ABSENT"}
            signed(source,prefix+"disposition",keys.selection,"PBA2/disposition",disposition)
        else:
            if type(counts[i]) is not int or not 0 < counts[i] <= MAX_COUNT:
                raise ValueError("invalid input count")
            raw = encode_vector(updates[i])
            if len(raw) != 8 * dimension:
                raise ValueError("dimension mismatch")
            opening = bytes.fromhex(digest("PBA2/opening", str(round_id).encode(), str(cid).encode(), raw))
            body = {"version":VERSION,"round":round_id,"model_hash":model_hash,"bulletin_hash":bulletin_pin,
                    "client_id":cid,"update_digest":digest("PBA2/update",raw,opening),
                    "declared_count":counts[i],"status":"SUBMITTED"}
            receipt = signed(source,prefix+"receipt",keys.clients[cid],"PBA2/client",body)
            state = {"slot":i,"client_id":cid,"status":"ACCEPTED","numerator":counts[i],
                     "policy_count":counts[i],"policy_version":POLICY["version"],
                     "receipt_digest":digest("PBA2/receipt",canon(receipt))}
            source[prefix+"opening"],source[prefix+"update"] = opening,raw
            accepted_vectors.append(updates[i]); nums.append(counts[i])
        put(source,prefix+"state",state); states.append(state)
    if not nums:
        raise ValueError("all-dropout round must abort rather than claim an aggregate")
    tree = Tree([leaf(s) for s in states])
    # Training can supply the bytes of the actual server-applied aggregate.
    source["result"] = actual_result if actual_result is not None else encode_vector(replay(accepted_vectors,nums,sum(nums)))
    snapshot = {"version":VERSION,"round":round_id,"bulletin_hash":bulletin_pin,"K":k,
                "state_root":tree.root,"denominator":sum(nums),"result_digest":digest("PBA2/result",source["result"])}
    env = signed(source,"snapshot",keys.server,"PBA2/server",snapshot)
    for i in range(k): put(source,f"record/{i}/state_proof",tree.proof(i))
    trust = Trust(keys.selection.public_key(),keys.server.public_key(),
                  {cid:key.public_key() for cid,key in keys.clients.items()},round_id,model_hash,
                  bulletin_pin,digest("PBA2/snapshot",canon(env)))
    return Fixture(source,trust,keys,k,dimension)


def tamper(fixture, kind, slots=(0,)):
    f = fixture.clone()
    for slot in slots:
        prefix = f"record/{slot}/"
        state = f.obj(prefix+"state")
        if kind == "update_replacement":
            vector = decode_vector(f.source[prefix+"update"],f.dimension); vector[0] += 1
            f.source[prefix+"update"] = encode_vector(vector)
        elif kind == "unsigned_insertion":
            rec=f.obj(prefix+"receipt"); rec["sig"]="00"*64; put(f.source,prefix+"receipt",rec); f.bind_receipt(slot)
        elif kind == "identity_exchange":
            other=(slot+1)%f.k
            f.source[prefix+"receipt"] = f.source[f"record/{other}/receipt"]; f.bind_receipt(slot)
        elif kind == "duplicate_record":
            other=(slot+1)%f.k
            duplicate=f.obj(f"record/{other}/state"); put(f.source,prefix+"state",duplicate)
        elif kind == "roster_omission":
            # Explicit shorter submitted state-set, not unavailable bytes.
            snap=f.obj("snapshot")["body"]; snap["K"]-=1; put(f.source,"snapshot",{"body":snap})
        elif kind == "unannounced_client":
            state["client_id"] = max(f.keys.clients)+100; put(f.source,prefix+"state",state)
        elif kind == "modified_declared_count":
            rec=f.obj(prefix+"receipt"); rec["body"]["declared_count"]+=1
            put(f.source,prefix+"receipt",rec); f.bind_receipt(slot)
        elif kind == "signed_false_declared_count":
            rec=f.obj(prefix+"receipt"); rec["body"]["declared_count"]+=100
            put(f.source,prefix+"receipt",rec); f.resign_receipt(slot)
            state=f.obj(prefix+"state"); state["numerator"]=state["policy_count"]=rec["body"]["declared_count"]
            put(f.source,prefix+"state",state)
        elif kind == "declared_count_policy":
            state["policy_count"]+=1; put(f.source,prefix+"state",state)
        elif kind == "rule_substitution":
            state["policy_version"]="equal-weights-unannounced"; put(f.source,prefix+"state",state)
        elif kind == "weight_inconsistency":
            state["numerator"]+=1; put(f.source,prefix+"state",state)
        elif kind == "status_policy_mismatch":
            state["status"]="REJECTED"; put(f.source,prefix+"state",state)
        elif kind == "timeout_disposition":
            require_absent = state["receipt_digest"] is None
            if not require_absent:
                raise ValueError("timeout fixture requires an unsubmitted slot")
            state["status"]="TIMEOUT"; put(f.source,prefix+"state",state)
            disposition = {"bulletin_hash": f.trust.bulletin_pin,
                           "client_id": state["client_id"], "slot": slot, "status":"TIMEOUT"}
            # The selection service signs the close observation; it is not a
            # server-generated assertion and is checked against the pinned bulletin.
            signed(f.source,prefix+"disposition",f.keys.selection,"PBA2/disposition",disposition)
        elif kind == "old_round_replay":
            rec=f.obj(prefix+"receipt"); rec["body"]["round"]-=1
            # Valid signature under client key on an old-context record: stronger than bit tampering.
            put(f.source,prefix+"receipt",rec); f.resign_receipt(slot)
        elif kind == "forged_bulletin":
            b=f.obj("bulletin"); b["body"]["roster_root"]="00"*32; put(f.source,"bulletin",b)
        elif kind in ("missing_evidence","forged_result","denominator_inconsistency","honest_round"):
            pass
        else:
            raise ValueError(kind)
    if kind == "forged_result":
        v=decode_vector(f.source["result"],f.dimension); v[0]+=1; f.source["result"]=encode_vector(v)
    if kind == "signed_false_declared_count":
        denominator=sum(f.obj(f"record/{i}/state")["numerator"] for i in range(f.k))
        f.commit(denominator=denominator,recompute=True)
    else:
        denominator=f.obj("snapshot")["body"]["denominator"] + 1 if kind=="denominator_inconsistency" else None
        f.commit(denominator=denominator,recompute=(kind=="denominator_inconsistency"))
    if kind == "missing_evidence":
        for slot in slots: f.source.pop(f"record/{slot}/opening",None)
    return f


def build_round(**kwargs):
    """Legacy development adapter; new runners use the typed Fixture/Trust API."""
    policy_slot=kwargs.pop("policy_override_slot",None)
    kwargs["model_hash"]=kwargs.pop("model_hash_override",None)
    selected=kwargs.pop("selected",None)
    if selected is not None: kwargs["absent_slots"]=set(range(kwargs.get("clients",10)))-set(selected)
    f=make_fixture(**kwargs)
    if policy_slot is not None: f=tamper(f,"declared_count_policy",(policy_slot,))
    return f.source, dict(f.trust.__dict__)


def mutate(source, kind, slot=0):
    """Legacy byte-corruption helper, not a committed-server attack fixture."""
    out=dict(source)
    if kind=="missing_evidence": out.pop(f"record/{slot}/opening",None)
    elif kind=="forged_result": out["result"]=bytes(len(out["result"]))
    else: raise ValueError("use tamper(Fixture, kind) for authenticated adversarial transcripts")
    return out
