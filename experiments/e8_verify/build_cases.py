# -*- coding: utf-8 -*-
"""E8 case builder: serialize 16 signed fixtures, 16 semantic tamper variants per
fixture, and byte-level randomized evidence mutations for the independent Go
verifier. Only public material and public keys leave this process.
"""
from __future__ import annotations
import base64, json, sys
from pathlib import Path

sys.path.insert(0, r".")
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from experiments.pba_v3.repository import Keys, make_fixture, tamper
from experiments.pba_v3.verify import audit

OUT = Path(r".\experiments\e8_verify\cases")
OUT.mkdir(parents=True, exist_ok=True)
N, DIM = 30, 256

KINDS = ("update_replacement", "unsigned_insertion", "identity_exchange", "duplicate_record",
         "roster_omission", "unannounced_client", "modified_declared_count",
         "signed_false_declared_count", "declared_count_policy", "rule_substitution",
         "weight_inconsistency", "status_policy_mismatch", "old_round_replay",
         "forged_result", "denominator_inconsistency", "missing_evidence")


def b64(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def pub(k):
    return k.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def trust_json(t):
    return {"selection_key": pub(t.selection_key), "server_key": pub(t.server_key),
            "registry": {str(cid): pub(k) for cid, k in sorted(t.registry.items())},
            "round_id": t.round_id, "model_hash": t.model_hash,
            "bulletin_pin": t.bulletin_pin, "snapshot_pin": t.snapshot_pin}


def expected(res):
    return {"outcome": res.outcome,
            "records": {str(k): v for k, v in sorted(res.record_outcomes.items())},
            "findings": [{"slot": f["slot"], "outcome": f["outcome"], "reason": f["reason"]} for f in res.findings]}


def diff(base, other):
    out = {}
    for name in base:
        if name not in other:
            out[name] = None
        elif other[name] != base[name]:
            out[name] = b64(other[name])
    for name in other:
        if name not in base:
            out[name] = b64(other[name])
    return out


def byteflip(src, name, pos):
    raw = bytearray(src[name])
    raw[pos % len(raw)] ^= 0x01
    return bytes(raw)


def randomized_mutants(base_objs, mutants):
    """Byte-level edits that do not rely on the semantic tamper() catalogue."""
    for i, base in enumerate(base_objs):
        fid, bid = f"f{i:02d}", f"b{i:02d}"
        ops = {
            "flip_opening": lambda s: {**s, "record/2/opening": byteflip(s, "record/2/opening", 0)},
            "flip_update": lambda s: {**s, "record/2/update": byteflip(s, "record/2/update", 7)},
            "flip_receipt_sig": lambda s: {**s, "record/2/receipt": byteflip(s, "record/2/receipt", 40)},
            "drop_state_proof": lambda s: {k: v for k, v in s.items() if k != "record/2/state_proof"},
        }
        for tag, fn in ops.items():
            f = base.clone()
            f.source = fn(dict(f.source))
            rm = audit(f.source, f.trust, slots=[2, 4, 7], full=False)
            mutants.append({"id": f"{fid}-random-{tag}", "base": bid, "full": False, "slots": [2, 4, 7],
                            "trust": trust_json(f.trust), "diff": diff(base.source, f.source),
                            "expected": expected(rm), "kind": "random-" + tag})
    for i in range(0, 16, 4):
        base = base_objs[i]
        rm = audit(base.source, base.trust, slots=[2, 2, 7], full=False)
        mutants.append({"id": f"f{i:02d}-random-duplicate_slot", "base": f"b{i:02d}", "full": False,
                        "slots": [2, 2, 7], "trust": trust_json(base.trust), "diff": {},
                        "expected": expected(rm), "kind": "random-duplicate_slot"})


def main():
    fixtures, mutants, base_export, base_objs = [], [], [], []
    for i in range(16):
        keys = Keys.generate(list(range(N)))
        absent = (11,) if i % 3 == 0 else ()
        base = make_fixture(round_id=100 + i, dimension=DIM, clients=N, seed=1000 + i,
                            keys=keys, absent_slots=absent)
        base_objs.append(base)
        base_export.append({"id": f"b{i:02d}", "source": {k: b64(v) for k, v in base.source.items()}})
        kind = ("honest", "update_replacement", "unsigned_insertion", "identity_exchange")[i % 4]
        f0 = base if kind == "honest" else tamper(base, kind, (2,))
        full = i % 4 == 0
        slots = list(range(N)) if full else [2, 4, 7]
        res = audit(f0.source, f0.trust, slots=slots, full=full)
        fixtures.append({"id": f"f{i:02d}", "full": full, "slots": slots, "round_id": 100 + i,
                         "trust": trust_json(f0.trust), "source": {k: b64(v) for k, v in f0.source.items()},
                         "expected": expected(res), "base_kind": kind})
        for kind2 in KINDS:
            slot = 2
            if kind2 == "timeout_disposition":
                if not absent:
                    continue
                slot = absent[0]
            try:
                fm = tamper(base, kind2, (slot,))
            except Exception as exc:
                print(f"skip f{i:02d}/{kind2}: {exc}")
                continue
            rm = audit(fm.source, fm.trust, slots=slots, full=full)
            mutants.append({"id": f"f{i:02d}-{kind2}", "base": f"b{i:02d}", "full": full, "slots": slots,
                            "trust": trust_json(fm.trust), "diff": diff(base.source, fm.source),
                            "expected": expected(rm), "kind": kind2})
    randomized_mutants(base_objs, mutants)
    cases = {"fixtures": fixtures, "mutants": mutants, "bases": base_export,
             "generator": {"rounds": [100, 115], "clients": N, "dimension": DIM,
                           "slots_sampled": [2, 4, 7], "full_fixtures": [f"f{i:02d}" for i in range(0, 16, 4)]}}
    path = OUT / "cases.json"
    path.write_text(json.dumps(cases, ensure_ascii=False), encoding="utf-8")
    from collections import Counter
    print("fixtures", len(fixtures), "mutants", len(mutants), "bytes", path.stat().st_size)
    print("fixture outcomes:", Counter(x["expected"]["outcome"] for x in fixtures))
    print("mutant outcomes:", Counter(x["expected"]["outcome"] for x in mutants))
    print("mutant kinds:", len({x["kind"] for x in mutants}))


if __name__ == "__main__":
    main()