# -*- coding: utf-8 -*-
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    manifest = ROOT / "MANIFEST_SHA256.txt"
    bad = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        path = ROOT / rel
        if not path.exists() or sha256(path) != digest:
            bad.append(rel)
    if bad:
        raise SystemExit(f"manifest mismatch: {bad[:10]}")
    print(f"manifest: OK ({sum(1 for _ in manifest.open(encoding='utf-8'))} files)")

    from experiments.pba_v3.repository import make_fixture, tamper
    from experiments.pba_v3.verify import audit, PASS
    from experiments.external_vrefl.vrefl_core import parameters, server_annotate, verify_fixture

    f = make_fixture(dimension=8, clients=10, seed=1)
    if audit(f.source, f.trust, slots=[0, 1, 2]).outcome != PASS:
        raise SystemExit("PBA/3 honest smoke failed")
    bases = parameters(8)
    server_annotate(f, bases)
    if verify_fixture(f, bases)[0] != PASS:
        raise SystemExit("VREFL honest smoke failed")
    forged = tamper(f, "forged_result", (0,))
    server_annotate(forged, bases)
    if verify_fixture(forged, bases)[0] == PASS:
        raise SystemExit("VREFL forged-result smoke failed")
    print("core smoke: OK")


if __name__ == "__main__":
    main()
