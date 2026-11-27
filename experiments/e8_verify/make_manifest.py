# -*- coding: utf-8 -*-
"""E8 manifest + per-case CSV, then print a summary for the report."""
import hashlib, json
from pathlib import Path

ROOT = Path(r".\experiments\e8_verify")
report = json.loads((ROOT / "go_report.json").read_text(encoding="utf-8"))
cases = json.loads((ROOT / "cases" / "cases.json").read_text(encoding="utf-8"))


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


files = [ROOT / "build_cases.py", ROOT / "cases" / "cases.json", ROOT / "go" / "main.go", ROOT / "go_report.json"]
manifest = {"cases": report["cases"], "agreements": report["agreements"], "mismatches": report["mismatches"],
            "fixtures": len(cases["fixtures"]), "mutants": len(cases["mutants"]),
            "semantic_kinds": sorted({m["kind"] for m in cases["mutants"]}),
            "sha256": {str(p.relative_to(ROOT)): sha(p) for p in files},
            "python_reference": "experiments/pba_v3 (verify.py, codec.py, repository.py)",
            "go_version": "go1.25.9 windows/amd64"}
(ROOT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

with (ROOT / "per_case.csv").open("w", encoding="utf-8") as fh:
    fh.write("case_id,expected,go,agree,findings\n")
    for r in report["reports"]:
        reasons = ";".join(f"{f['outcome']}:{f['reason']}" for f in (r.get("findings") or []))
        fh.write(f'{r["id"]},{r["expected"]},{r["outcome"]},{"yes" if not r["mismatch"] else "no"},"{reasons}"\n')
print(json.dumps({k: manifest[k] for k in ("cases", "agreements", "mismatches", "fixtures", "mutants")}, ensure_ascii=False))
print("kinds", len(manifest["semantic_kinds"]))
