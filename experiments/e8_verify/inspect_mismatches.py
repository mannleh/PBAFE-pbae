# -*- coding: utf-8 -*-
import json
from collections import Counter

p = r".\experiments\e8_verify\go_report.json"
s = json.load(open(p, encoding="utf-8"))
bad = [r for r in s["reports"] if r["mismatch"]]
print("mismatches", len(bad))
print(Counter((r["expected"], r["outcome"]) for r in bad))
for r in bad[:40]:
    recdiff = {k: (v, r["expected"]) for k, v in r["records"].items() if False}
    print(f"{r['id']:<46} expected={r['expected']:<22} go={r['outcome']}")
# record-level diffs
cases = json.load(open(r".\experiments\e8_verify\cases\cases.json", encoding="utf-8"))
exp = {x["id"]: x["expected"] for x in cases["fixtures"]}
for m in cases["mutants"]:
    exp[m["id"]] = m["expected"]
count = 0
for r in bad:
    e = exp[r["id"]]["records"]
    d = {k: (e.get(k), r["records"].get(k)) for k in set(e) | set(r["records"]) if e.get(k) != r["records"].get(k)}
    if d:
        print("REC", r["id"], d)
        count += 1
        if count > 20:
            break
