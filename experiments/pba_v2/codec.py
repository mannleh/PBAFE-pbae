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

