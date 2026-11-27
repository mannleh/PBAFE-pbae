# VREFL verification-core baseline comparison

## Purpose

This experiment closes the R1-10 / R3-1 gap by running an existing verifiable-FL method's verification core on the same bridge fixture as PBA/3. The external method is VREFL (Ye et al., *Journal of Network and Computer Applications* 207 (2022) 103486, doi:10.1016/j.jnca.2022.103486).

## Scope and trust model

The comparison is explicitly at the **aggregation-verification-core level**:

- Implemented: VREFL's linearly homomorphic hash (LHH), Merkle commitment, signature checks, and fixed-point weighted-aggregate verification.
- Not implemented: VREFL's pairwise masks, CRT reconnection, noise server, cluster-head deployment, or privacy claims.
- The original VREFL assumes a semi-honest central server and non-colluding cluster/noise roles. Here the server fixture may be malicious, while the verifier is authorized and trusted, matching PBA/3's auditor role. This is therefore a mechanism-level runtime comparison, not a full protocol-security equivalence.
- The experimental group uses p = 2^127 - 1 and SHA-256-derived distinct bases. It is not a production parameter recommendation.

## Core validation

| Fixture | VREFL-core outcome |
|---|---|
| Honest aggregate | PASS |
| Forged published result | FAIL_RESULT_REPLAY |
| Missing accepted opening | INCONCLUSIVE_EVIDENCE |
| `drop_client` declared-policy violation | PASS |
| Update replacement | FAIL_ROSTER |

The `drop_client` result is expected: VREFL verifies aggregate consistency over accepted uploads but does not establish PBA/3's declared-policy contract.

## Runtime comparison

Data: released UNSW-NB15 bridge fixture, 30 clients, 10 selected per round, 60 rounds, seeds 310001-310020. PBA/3 spot arms are the released 200 bridge runs; PBA-full and VREFL-full add 40 runs each. All arms share data, attack/withholding traces, client-selection streams, controller, and metrics.

| Scenario | Method | Applied violations | Compliant retained | Discard fraction | F1 | Audit MB | Verification CPU s |
|---|---|---:|---:|---:|---:|---:|---:|
| mixed | no audit | 22.35 | 0.00 | 0.0000 | 0.7297 | 0.000 | 0.000 |
| mixed | uniform b=3 | 17.95 | 1.75 | 0.1025 | 0.7277 | 3.156 | 0.836 |
| mixed | adaptive b=3 | 8.30 | 7.05 | 0.3517 | 0.7156 | 2.583 | 0.780 |
| mixed | neutral b=3 | 10.10 | 1.50 | 0.2292 | 0.7190 | 2.691 | 0.787 |
| mixed | separated b=3 | 8.30 | 3.85 | 0.2983 | 0.7186 | 2.653 | 0.802 |
| mixed | PBA-full | 0.00 | 8.75 | 0.5183 | 0.7121 | 32.039 | 18.605 |
| mixed | VREFL-full | 16.10 | 5.65 | 0.1983 | 0.7273 | 26.060 | 80.534 |
| withholding | no audit | 0.00 | 0.00 | 0.0000 | 0.7511 | 0.000 | 0.000 |
| withholding | uniform b=3 | 0.00 | 3.70 | 0.0617 | 0.7499 | 3.289 | 0.873 |
| withholding | adaptive b=3 | 0.00 | 16.25 | 0.2708 | 0.7485 | 2.969 | 0.821 |
| withholding | neutral b=3 | 0.00 | 3.70 | 0.0617 | 0.7499 | 3.289 | 0.859 |
| withholding | separated b=3 | 0.00 | 9.30 | 0.1550 | 0.7502 | 3.198 | 0.831 |
| withholding | PBA-full | 0.00 | 20.00 | 0.3333 | 0.7461 | 33.882 | 22.098 |
| withholding | VREFL-full | 0.00 | 11.90 | 0.1983 | 0.7491 | 27.242 | 83.892 |

## Main paired contrasts

- VREFL-full minus PBA-neutral (mixed): **+6.00 applied violations** [3.35, 8.85], **+4.15 compliant retained** [3.35, 5.10], **+23.37 MB** [22.85, 23.89], and **+79.75 s** verification CPU. The F1 difference is +0.0083 [−0.0037, +0.0256] and is not resolved.
- VREFL-full minus PBA-full (mixed): **+16.10 applied violations** [14.85, 17.35], but **−3.10 compliant retained** [−3.65, −2.55] and **−5.98 MB** [−6.51, −5.45]. The F1 difference is +0.0152 [−0.0029, +0.0367] and is not resolved.
- Under withholding, VREFL-full retains 11.90 compliant rounds versus 20.00 for PBA-full and 3.70 for PBA-neutral. It therefore sits between PBA spot and PBA full on availability cost.

## Interpretation

PBA-neutral's advantage is not a comparison against a weakened scheduling rule. Against an existing verifiable-FL verification core it achieves better declared-policy containment and lower compliant suppression at about **9.7× lower audit traffic** and **102× lower verification CPU** than VREFL-full. VREFL-full is less wasteful than PBA-full under withholding, but it does not detect the declared-policy violation that PBA-full catches. This is direct runtime evidence for the paper's scope–budget–response contribution.

## Artifacts

- `experiments/external_vrefl/vrefl_core.py`
- `experiments/external_vrefl/run_vrefl_baseline.py`
- `experiments/external_vrefl/run_pba_full_bridge.py`
- `experiments/external_vrefl/summarize_vrefl.py`
- `experiments/external_vrefl/results_bridge/`
- `experiments/external_vrefl/results_pba_full/`
