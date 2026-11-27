# E8 — Independent second verification core + differential evidence tests

Status: **complete, local only** (repository initialized locally; nothing pushed to any remote, as instructed).
Location: `experiments/e8_verify` (Go core in `go/`, cases in `cases/`, report in `go_report.json`).

## 1. What was built

A second implementation of the record-level audit decision in **Go 1.25 using only the standard library** (`crypto/ed25519`, `crypto/sha256`), independent of the Python reference in `experiments/pba_v3`:

| layer | Python reference | Go core |
|---|---|---|
| canonical JSON | `json.dumps(sort_keys, ensure_ascii=True, separators=(',',':'))` | hand-written ASCII escaper + sorted-key writer |
| domain digest | `sha256(len(part)‖part …)` per domain | same rule, independent implementation |
| signatures | `cryptography` Ed25519 over digest-of-body | `crypto/ed25519.Verify` |
| Merkle | `Tree` / `check_proof`, duplicated last node | independent `checkProof` / `treeRoot` |
| vectors | struct big-endian int64, ±10⁹ | `binary.BigEndian` int64, ±10⁹ |
| replay | exact rational, ties-to-even, bigint | `math/big`, ties-to-even |
| precedence | FAIL_ROSTER > FAIL_POLICY > FAIL_RESULT_REPLAY > INCONCLUSIVE | same |

## 2. Coverage actually exercised

- 16 signed fixtures: honest / update replacement / unsigned insertion / identity exchange; 4 full-scope, 12 sampled `b = 3`; 30 clients; dimension 256.
- 324 tampered variants: 16 semantic families × 16 fixtures (update replacement, unsigned insertion, identity exchange, duplicate record, roster omission, unannounced client, modified and signed-false declared count, policy substitutions, weight inconsistency, status mismatch, old-round replay, forged result, denominator inconsistency, missing evidence, timeout disposition) plus byte-level randomized mutations (opening flip, update flip, receipt-signature flip, state-proof removal, duplicate slot).
- Outcome mix: 192 FAIL_ROSTER, 68 FAIL_POLICY, 4 FAIL_RESULT_REPLAY, 32 INCONCLUSIVE_EVIDENCE, 44 PASS — all five classes are represented, so agreement is not dominated by one label.

## 3. Result

**340/340 cases agree, 0 mismatches** — identical overall outcome and identical per-record outcome for every case. Artifacts: `go_report.json`, `per_case.csv`, `manifest.json` (SHA-256 of generator, cases, Go source, report).

Reproduce:
```powershell
$env:PYTHONPATH="."
python experiments\e8_verify\build_cases.py
cd experiments\e8_verify\go; go build -o pbaverify.exe .; .\pbaverify.exe -cases ..\cases\cases.json -out ..\go_report.json
```

## 4. Honest limits

1. **This is an implementation-differential test, not independent protocol design.** The expected labels come from the Python reference; agreement proves both implementations read the same signed bytes to the same decision. It does not prove the policy is semantically right — that obligation stays with the paper's theorems and the negative controls.
2. The Go core covers the **record-level** path; the PBA/3 segment tier is not re-implemented.
3. No network/OS measurements here (E6 covers overhead), and no private keys are exported — only public objects, public keys and pins.
4. The repository is local (`git init`, two commits); creating a public remote and pushing is a separate, explicitly authorized step that has **not** been taken.

## 5. What the letter can say

- "An independent verifier in a different language and cryptographic library reproduces 340/340 decisions (overall and per record) on 16 signed fixtures and 324 tampered variants, including byte-level evidence mutations; the differential harness and case generator are included in the artifact."
- Do **not** say "formally verified" or "independent implementation of the protocol"; say "independent implementation of the decision path".

## 6. Local repository

`experiments/e8_verify` is a git repository with `.gitignore` (build products excluded), `README.md`, generator, Go source, cases, manifest, per-case CSV and this report. Remote: none.
