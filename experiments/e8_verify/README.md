# PBA/3 verifier — independent second core (Go)

This directory is a self-contained, locally committed artifact for the revision of
COMPELECENG-D-26-10605. It contains a **second implementation of the record-level
audit decision** written in Go, using only the standard library
(`crypto/ed25519`, `crypto/sha256`), plus a differential harness against the
Python reference verifier.

No private key, no training data and no client payload is included: the cases
carry only signed public objects, public keys and pin values.

## What is compared

* 16 signed fixtures (honest, update replacement, unsigned insertion, identity
  exchange; sampled `b = 3` and full `b = 30`; 30 clients, dimension 256).
* 324 tampered variants: 16 semantic tamper families × 16 fixtures, plus
  byte-level randomized evidence mutations (opening flip, update flip, receipt
  signature flip, state-proof removal, duplicate slot selection).
* For every case the Go core must reproduce **both** the overall outcome
  (`PASS`, `FAIL_ROSTER`, `FAIL_POLICY`, `FAIL_RESULT_REPLAY`,
  `INCONCLUSIVE_EVIDENCE`) and every per-record outcome.

Current result: **340/340 cases agree, 0 mismatches.**

## Why this is not just re-labeling

The expected labels are produced by the Python reference; agreement proves the
two implementations derive the same decision from the same signed bytes, not
that either is semantically correct. Correctness of the policy itself is covered
by the paper's theorem/proof obligations and by the negative controls in the
tamper catalogue (each family is expected to fail for a specific reason).

The Go core re-derives, independently:

* canonical JSON (sorted keys, ASCII escapes) and its byte equality with stored objects,
* SHA-256 domain-separated digests with 8-byte big-endian length prefixes,
* Ed25519 envelope verification over the digest of the canonical body,
* Merkle membership with the duplicated-last-node rule,
* integer vector decoding (big-endian int64, ±10^9 bound),
* exact signed rational replay with ties-to-even (big.Int),
* outcome precedence `FAIL_ROSTER > FAIL_POLICY > FAIL_RESULT_REPLAY > INCONCLUSIVE`.

## Reproduce

```powershell
$env:PYTHONPATH="."
python experiments\e8_verify\build_cases.py
cd experiments\e8_verify\go
go build -o pbaverify.exe .
.\pbaverify.exe -cases ..\cases\cases.json -out ..\go_report.json
```

`build_cases.py` uses the frozen Python reference (`experiments/pba_v3`) to
produce expectations; `go/main.go` never imports Python code.

## Honest limits

* Same fixtures, same trust inputs: this is an implementation-differential test,
  not an independent protocol re-derivation from the paper text.
* No network, no clock, no OS-level isolation; wall-clock and memory are not
  measured here (that is E6's job).
* The Go core implements the record-level audit path; the PBA/3 segment tier is
  out of scope for this artifact.
