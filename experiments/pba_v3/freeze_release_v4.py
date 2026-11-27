"""P5.4: freeze release_v4.

Copies the artifacts the manuscript cites into the submission tree and writes a
manifest with hashes, so a later edit to any source number is detectable.
"""
import hashlib
import json
import shutil
from datetime import date
from pathlib import Path

SRC = Path("experiments/pba_v3/results")
DST = Path("submission_v4/experiments/pba_v2/results/release_v4")

ARTIFACTS = [
    "a_manipulation_onset9.json",
    "b_segment_v3.json",
    "c_sweep_v1.json",
    "tier_cost.json",
    "protocol_v4.json",
    "protocol_oracle_v4.json",
]


def sha(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    DST.mkdir(parents=True, exist_ok=True)
    manifest = {"release": "PBA/3 release_v4", "frozen": str(date.today()),
                "config": "PBA3/config-v1", "artifacts": {}}
    for name in ARTIFACTS:
        src = SRC / name
        if not src.exists():
            raise SystemExit(f"missing artifact: {src}")
        dst = DST / name
        shutil.copy2(src, dst)
        manifest["artifacts"][name] = {"sha256": sha(dst), "bytes": dst.stat().st_size}
    for name in ("result_macros.tex",):
        p = DST / "tex" / name
        if p.exists():
            manifest["artifacts"][f"tex/{name}"] = {"sha256": sha(p), "bytes": p.stat().st_size}
    (DST / "reproducibility_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")
    print(json.dumps({"frozen": manifest["frozen"], "files": len(manifest["artifacts"])}, indent=2))


if __name__ == "__main__":
    main()
