# PBA/3 reproducibility package (anonymous, public)

Manuscript: COMPELECENG-D-26-10605  
Title: Policy-Bound Auditing for Federated Edge Intrusion Detection under Limited Verification Budgets  
Public repository: https://github.com/mannleh/PBAFE-pbae  
Status: self-contained anonymized package publicly deposited at the repository above.

## Contents

- `experiments/pba_v3/`: protocol, verifier, schedulers, training bridge, tests, and the released UNSW-NB15 results.
- `experiments/e1_edge/`: Edge-IIoTset preparation, E1-L main grid, paired model-capacity test, and initial bounded pilot.
- `experiments/e2_*`, `e3_*`, `e4_*`, `e5_*`, `e6_*`, `e7_*`, `e8_*`, `e11_*`, `e12_*`, `e13_*`: supporting experiments and per-seed/per-cell outputs.
- `experiments/external_vrefl/`: VREFL verification-core baseline, PBA-full control, and comparison summaries.
- `data/`: processed UNSW-NB15 and Edge-IIoTset subsets with manifests and SHA-256 hashes. Raw multi-GB source corpora are not redistributed.
- `MANIFEST_SHA256.txt`: SHA-256 for every packaged file except the manifest itself.
- `PACKAGE_INFO.json`: scope, exclusions, environment, and curation notes.
- `DATA_LICENSES.md`: dataset citations, license links, reuse conditions, and preprocessing changes.
- `verify_package.py`: hash check plus core protocol/VREFL smoke tests.

## Environment

- Python 3.12 (validated with 3.12.15)
- numpy 2.5.2, pandas 3.0.5, scikit-learn 1.9.0, cryptography 50.0.2, psutil
- Go 1.25 (for the independent E8 verifier)

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Run all commands from the package root. Absolute workspace paths in archived scripts/configs have been replaced with `.` so the package is relocatable on Windows.

## Quick verification

```bash
python verify_package.py
```

Expected: all manifest hashes match; a sampled PBA/3 audit returns PASS; the VREFL core returns PASS for an honest fixture and FAIL_RESULT_REPLAY for a forged result.

## Reproduction map

- Original UNSW scheduling/response: `experiments/pba_v3/`
- Edge-IIoTset large-grid preparation: `experiments/e1_edge/prepare_edgeiiot_large.py`
- E1-L main grid: `experiments/e1_edge/run_e1_large.py`
- Paired 6,249/49,941 capacity test: `experiments/e1_edge/run_edge_capacity.py`
- Reactive adversary: `experiments/e3_reactive/`
- Common byte budget: `experiments/e11_bytebudget/`
- External VREFL core: `experiments/external_vrefl/run_vrefl_baseline.py`
- Matched PBA-full control: `experiments/external_vrefl/run_pba_full_bridge.py`
- Summaries: `experiments/e1_edge/summarize_e1_large.py`, `summarize_edge_capacity.py`, and `experiments/external_vrefl/summarize_vrefl.py`

Raw data acquisition: use the official UNSW-NB15 distribution and the Edge-IIoTset DOI recorded in the experiment manifests. Processed arrays and client indices required to rerun the reported experiments are included.

## Scope notes

- E9 and E10 are analysis-only entries in the response letter; they have no separate run directories.
- The VREFL baseline reproduces the LHH + Merkle verification core, not pairwise masks, CRT reconnection, or the full three-role deployment.
- E8 is an implementation-differential test against Python reference decisions, not an independent protocol re-derivation.
- No author names, affiliations, emails, Git remotes, build products, caches, failed runs, or raw multi-GB datasets are included.
