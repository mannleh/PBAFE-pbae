"""Segment-sum tier: fixture construction and adversarial variants.

Server publishes, per segment, the sum of per-record contributions
    Sigma_s = sum_i n_i * delta_{i,s}
together with a commitment to every (segment, record) contribution. An
auditor that samples segment s can then recompute the whole segment from the
record-level evidence it already retrieves and compare against the published
sum. This is a genuine middle tier: it reads far less than a full replay, but
it can contradict a published aggregate, which the record tier cannot.
"""
from dataclasses import replace

import numpy as np

from experiments.pba_v3.codec import (Tree, canon, contribution, decode_vector,
                                      digest, encode_vector, leaf, seg_bounds,
                                      segment_index, segment_sums, sign)
from experiments.pba_v3.repository import POLICY, make_fixture, put


def build_segment_fixture(round_id=1, dimension=64, clients=10, segments=4, seed=7, **kw):
    f = make_fixture(round_id=round_id, dimension=dimension, clients=clients, seed=seed, **kw)
    return add_segments(f, segments)


def add_segments(f, segments, tamper_segment=None, tamper_delta=1, tamper_segments=None):
    """Attach segment commitments to an existing fixture and re-sign the
    snapshot.

    ``tamper_segments`` corrupts the published sum of every listed segment
    while leaving the per-record commitments untouched. Corrupting one segment
    per call and re-deriving in between would silently undo earlier tampering,
    so the API takes the whole set at once.
    """
    f = f.clone()
    bounds = seg_bounds(f.dimension, segments)
    accepted = [i for i in range(f.k) if f.obj(f"record/{i}/state")["status"] == "ACCEPTED"]
    contribs = []
    for i in accepted:
        vec = decode_vector(f.source[f"record/{i}/update"], f.dimension)
        n = f.obj(f"record/{i}/state")["numerator"]
        per_seg = [contribution(vec[lo:hi], n) for lo, hi in bounds]
        contribs.append(per_seg)
        for s, c in enumerate(per_seg):
            put(f.source, f"record/{i}/contribution/{s}", c)

    leaves = []
    for s in range(segments):
        for idx, c in enumerate(contribs):
            leaves.append(leaf({"segment": s, "record": idx, "contribution": c[s]}))
    tree = Tree(leaves)
    for s in range(segments):
        for idx in range(len(accepted)):
            put(f.source, f"segment/{s}/proof/{idx}",
                tree.proof(segment_index(idx, s, len(accepted))))

    sums = segment_sums(contribs, segments)
    bad = set(tamper_segments or ())
    if tamper_segment is not None:
        bad.add(tamper_segment)
    for s in bad:
        sums[s][0] += tamper_delta
    for s, total in enumerate(sums):
        put(f.source, f"segment/{s}", total)

    body = f.obj("snapshot")["body"]
    body["segment_count"] = segments
    body["segment_root"] = tree.root
    body["accepted"] = len(accepted)
    env = sign(f.keys.server, "PBA2/server", body)
    put(f.source, "snapshot", env)
    f.trust = replace(f.trust, snapshot_pin=digest("PBA2/snapshot", canon(env)))
    return f
