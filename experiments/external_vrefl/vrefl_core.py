# -*- coding: utf-8 -*-
"""VREFL verification core adapted to fixed-point weighted FL aggregation.

This is an independent implementation of the paper's linearly homomorphic hash
and Merkle commitment path. Secure aggregation masks, CRT reconnection and the
three-role deployment are not reproduced; the comparison is explicitly at the
aggregation-verification-core level.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace

from experiments.pba_v3.codec import canon, decode_vector, digest, replay
from experiments.pba_v3.repository import signed
from experiments.pba_v3.verify import FAIL_RESULT_REPLAY, FAIL_ROSTER, INCONCLUSIVE, PASS, verify

PRIME = (1 << 127) - 1
GENERATOR = 5
_PARAM_CACHE = {}


def parameters(dimension: int):
    if dimension not in _PARAM_CACHE:
        bases = []
        for i in range(dimension):
            material = hashlib.sha256(f"VREFL/LHH/base/{i}".encode("ascii")).digest()
            exponent = int.from_bytes(material, "big") % (PRIME - 2) + 2
            bases.append(pow(GENERATOR, exponent, PRIME))
        if len(set(bases)) != dimension:
            raise AssertionError("LHH bases are not distinct")
        _PARAM_CACHE[dimension] = tuple(bases)
    return _PARAM_CACHE[dimension]


def lhh_hash(vector, bases):
    value = 1
    for base, coordinate in zip(bases, vector):
        if coordinate:
            value = value * pow(base, int(coordinate), PRIME) % PRIME
    return value


def _leaf(slot: int, value: int):
    payload = b"VREFL/LHH/leaf" + slot.to_bytes(8, "big") + value.to_bytes(16, "big")
    return hashlib.sha256(payload).digest()


def merkle_root(leaves):
    if not leaves:
        return hashlib.sha256(b"VREFL/empty").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def _accepted(f):
    for slot in range(f.k):
        state = f.obj(f"record/{slot}/state")
        if state["status"] == "ACCEPTED":
            yield slot, state


def server_annotate(fixture, bases):
    hashes, leaves = {}, []
    aggregate_hash = 1
    for slot, state in _accepted(fixture):
        raw = fixture.source[f"record/{slot}/update"]
        vector = decode_vector(raw, fixture.dimension)
        value = lhh_hash(vector, bases)
        hashes[slot] = value
        leaves.append(_leaf(slot, value))
        aggregate_hash = aggregate_hash * pow(value, int(state["numerator"]), PRIME) % PRIME
    snapshot = fixture.obj("snapshot")["body"]
    snapshot["vrefl_merkle_root"] = merkle_root(leaves)
    snapshot["vrefl_aggregate_hash"] = f"{aggregate_hash:032x}"
    envelope = signed(fixture.source, "snapshot", fixture.keys.server, "PBA2/server", snapshot)
    fixture.trust = replace(fixture.trust,
                            snapshot_pin=digest("PBA2/snapshot", canon(envelope)))
    return hashes


def verify_fixture(fixture, bases):
    start = time.perf_counter_ns()
    bytes_read = 0
    try:
        snapshot_env = json.loads(fixture.source["snapshot"])
        bytes_read += len(fixture.source["snapshot"])
        snapshot = verify(fixture.trust.server_key, "PBA2/server", snapshot_env)
        if digest("PBA2/snapshot", canon(snapshot_env)) != fixture.trust.snapshot_pin:
            return FAIL_ROSTER, {"bytes_read": bytes_read, "cpu_ms": (time.perf_counter_ns()-start)/1e6,
                                 "records_read": 0, "reason": "snapshot pin mismatch"}

        hashes, leaves, vectors, weights = {}, [], [], []
        aggregate_hash = 1
        numerator = [0] * fixture.dimension
        records_read = 0
        for slot, state in _accepted(fixture):
            prefix = f"record/{slot}/"
            required = (prefix + "opening", prefix + "update", prefix + "receipt", prefix + "state")
            if any(name not in fixture.source for name in required):
                return INCONCLUSIVE, {"bytes_read": bytes_read, "cpu_ms": (time.perf_counter_ns()-start)/1e6,
                                      "records_read": records_read, "reason": f"missing accepted evidence at slot {slot}"}
            receipt_raw = fixture.source[prefix + "receipt"]
            opening = fixture.source[prefix + "opening"]
            update = fixture.source[prefix + "update"]
            state_raw = fixture.source[prefix + "state"]
            bytes_read += len(receipt_raw) + len(opening) + len(update) + len(state_raw)
            receipt = verify(fixture.trust.registry[state["client_id"]], "PBA2/client",
                             json.loads(receipt_raw))
            if receipt["update_digest"] != digest("PBA2/update", update, opening):
                return FAIL_ROSTER, {"bytes_read": bytes_read, "cpu_ms": (time.perf_counter_ns()-start)/1e6,
                                     "records_read": records_read, "reason": f"update commitment mismatch at slot {slot}"}
            vector = decode_vector(update, fixture.dimension)
            value = lhh_hash(vector, bases)
            weight = int(state["numerator"])
            hashes[slot] = value
            leaves.append(_leaf(slot, value))
            aggregate_hash = aggregate_hash * pow(value, weight, PRIME) % PRIME
            for i, coordinate in enumerate(vector):
                numerator[i] += coordinate * weight
            vectors.append(vector)
            weights.append(weight)
            records_read += 1

        root = merkle_root(leaves)
        if root != snapshot.get("vrefl_merkle_root") or f"{aggregate_hash:032x}" != snapshot.get("vrefl_aggregate_hash"):
            return FAIL_RESULT_REPLAY, {"bytes_read": bytes_read, "cpu_ms": (time.perf_counter_ns()-start)/1e6,
                                        "records_read": records_read, "reason": "LHH/Merkle aggregate mismatch"}
        expected = replay(vectors, weights, sum(weights))
        if decode_vector(fixture.source["result"], fixture.dimension) != expected:
            return FAIL_RESULT_REPLAY, {"bytes_read": bytes_read, "cpu_ms": (time.perf_counter_ns()-start)/1e6,
                                        "records_read": records_read, "reason": "fixed-point result mismatch"}
        return PASS, {"bytes_read": bytes_read, "cpu_ms": (time.perf_counter_ns()-start)/1e6,
                      "records_read": records_read, "reason": "verified"}
    except (KeyError, ValueError) as exc:
        return INCONCLUSIVE, {"bytes_read": bytes_read, "cpu_ms": (time.perf_counter_ns()-start)/1e6,
                              "records_read": 0, "reason": repr(exc)}
