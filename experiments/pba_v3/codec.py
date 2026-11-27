"""Bounded deterministic integer encoding. No floating-point replay."""
import hashlib
import json
import struct

VERSION = "PBA/2"
MAX_COORD = 10**9
MAX_COUNT = 10**6
MAX_CLIENTS = 10000
SCALE = 10**6


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(domain, *parts):
    h = hashlib.sha256()
    for part in (domain.encode("ascii"),) + parts:
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.hexdigest()


def sign(key, domain, obj):
    return {"body": obj, "sig": key.sign(bytes.fromhex(digest(domain, canon(obj)))).hex()}


def verify(key, domain, obj):
    key.verify(bytes.fromhex(obj["sig"]), bytes.fromhex(digest(domain, canon(obj["body"]))))
    return obj["body"]


def encode_vector(values):
    values = list(values)
    if not values or any(type(v) is not int or abs(v) > MAX_COORD for v in values):
        raise ValueError("integer coordinate outside the agreed domain")
    return struct.pack(">" + "q" * len(values), *values)


def decode_vector(raw, dimension):
    if len(raw) != dimension * 8:
        raise ValueError("incorrect vector length")
    values = list(struct.unpack(">" + "q" * dimension, raw))
    if any(abs(v) > MAX_COORD for v in values):
        raise ValueError("coordinate bound")
    return values


def round_even(n, d):
    """Exact signed rational to integer, ties to even; bigint numerator."""
    if type(d) is not int or d <= 0:
        raise ValueError("invalid denominator")
    q, r = divmod(abs(n), d)
    q += int(2 * r > d or (2 * r == d and q % 2 == 1))
    return q if n >= 0 else -q


def replay(vectors, numerators, denominator):
    if not vectors or len(vectors) != len(numerators):
        raise ValueError("missing replay inputs")
    d = len(vectors[0])
    if any(len(v) != d for v in vectors):
        raise ValueError("inconsistent dimension")
    return [round_even(sum(v[j] * n for v, n in zip(vectors, numerators)), denominator)
            for j in range(d)]


def leaf(obj):
    return digest("PBA2/leaf", canon(obj))


class Tree:
    """Repository-side construction; never called by the spot verifier."""
    def __init__(self, leaves):
        if not leaves:
            raise ValueError("empty tree")
        self.levels = [list(leaves)]
        while len(self.levels[-1]) > 1:
            row = self.levels[-1]
            self.levels.append([digest("PBA2/node", bytes.fromhex(row[j]),
                                      bytes.fromhex(row[min(j + 1, len(row) - 1)]))
                                for j in range(0, len(row), 2)])
        self.root = self.levels[-1][0]

    def proof(self, index):
        proof = []
        for row in self.levels[:-1]:
            proof.append(row[min(index ^ 1, len(row) - 1)])
            index //= 2
        return proof


def check_proof(value, index, count, proof, root):
    if type(index) is not int or not 0 <= index < count:
        return False
    if len(proof) != (count - 1).bit_length():
        return False
    h, width = value, count
    for sib in proof:
        if width % 2 and index == width - 1 and sib != h:
            return False
        left, right = (sib, h) if index % 2 else (h, sib)
        h = digest("PBA2/node", bytes.fromhex(left), bytes.fromhex(right))
        index //= 2
        width = (width + 1) // 2
    return h == root



# --- PBA/3: commit-before-reveal challenge derivation -----------------------

def derive_challenge_seed(bulletin_digest, round_id, beacon):
    """Challenge seed = H(domain || bulletin || round || beacon).

    The bulletin is signed before submissions; the beacon is external and
    unpredictable to the aggregation server at commit time. Together they let
    the auditor fix the challenge set before the round's evidence is served,
    without letting the server predict it.
    """
    if isinstance(beacon, str):
        beacon = beacon.encode("ascii")
    return digest("PBA3/challenge", bulletin_digest.encode("ascii"),
                  int(round_id).to_bytes(8, "big"), beacon)


def sealed_sample(seed_hex, weights, budget):
    """Deterministic weighted sampling without replacement.

    Determinism is a requirement, not a convenience: an auditor must be able
    to prove after the fact that the challenge set it used was the one fixed
    by (bulletin, round, beacon). Any private RNG state would break that.
    """
    import numpy as np
    weights = np.asarray(weights, dtype=float)
    if weights.ndim != 1 or len(weights) == 0:
        raise ValueError("weights must be a nonempty vector")
    if np.any(weights < 0) or not np.isfinite(weights).all():
        raise ValueError("weights must be finite and nonnegative")
    if not 0 <= budget <= len(weights):
        raise ValueError("budget outside [0, n]")
    rng = np.random.default_rng(int(seed_hex[:32], 16))
    p = weights / weights.sum() if weights.sum() > 0 else None
    return sorted(int(x) for x in rng.choice(len(weights), size=budget,
                                             replace=False, p=p))


# --- PBA/3: segment-sum commitments ---------------------------------------

def seg_bounds(dimension, segments):
    """Contiguous, deterministic partition of [0, dimension) into ``segments``
    nonempty parts. The remainder goes to the earliest segments so the split is
    stable across hosts and languages."""
    if segments < 1 or segments > dimension:
        raise ValueError("segments must be in [1, dimension]")
    base, rem = divmod(dimension, segments)
    out, start = [], 0
    for s in range(segments):
        width = base + (1 if s < rem else 0)
        out.append((start, start + width))
        start += width
    return out


def seg_vector(vector, bounds):
    lo, hi = bounds
    return list(vector[lo:hi])


def contribution(seg_values, numerator):
    """Per-record contribution to a segment numerator: n_i * delta_i,s."""
    return [int(numerator) * int(v) for v in seg_values]


def contribution_digest(bounds, contrib):
    return digest("PBA3/contribution", canon(list(bounds)), canon(contrib))


def segment_commitment(contributions, segments):
    """Commit to every (segment, accepted-record) contribution.

    Leaves are ordered by (segment, record index) so the tree is canonical.
    A server cannot publish a segment sum that disagrees with the committed
    per-record contributions without breaking this root.
    """
    leaves = []
    for s in range(segments):
        for idx, c in enumerate(contributions):
            leaves.append(leaf({"segment": s, "record": idx, "contribution": c[s]}))
    if not leaves:
        raise ValueError("no accepted contributions")
    return Tree(leaves)


def segment_index(record_index, s, records):
    return s * records + record_index


def segment_sums(contributions, segments):
    """Server-side sum per segment, committed in the signed snapshot."""
    out = []
    for s in range(segments):
        out.append([sum(c[s][j] for c in contributions) for j in range(len(contributions[0][s]))])
    return out
