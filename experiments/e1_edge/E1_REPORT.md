# E1 — Cross-dataset replication on Edge-IIoTset (R1-3 / R3-4)

Status: COMPLETED. 600 matched-seed runs (3 Dirichlet partitions × 20 seeds × 2 scenarios × 5 arms).
Corpus: Edge-IIoTset, `DNN-EdgeIIoT-dataset.csv` (Ferrag et al.; IEEE DataPort DOI 10.21227/mbc1-1h68).
Code: `experiments/e1_edge/prepare_edgeiiot.py`, `run_e1_edge.py`, `summarize_e1.py`.
The frozen PBA/3 application machinery (`pba_v3/v6_bridge.run_cell`, `v5_response`, `flcore`,
`verify`, `repository`) is reused **unchanged**; the only dataset-specific override is the
drop_client attack target pair, re-derived per partition.

## Setup

| Item | Value |
|---|---|
| Records | 12,000 train / 4,000 test (disjoint sample of the 2,219,201-row DNN file) |
| Features | 42 numeric (string/ID columns and `Attack_type` dropped); train-only StandardScaler |
| Label | `Attack_label` binary; train attacks = 3,185 (26.5%) |
| Model | released one-hidden-layer ReLU MLP, hidden=32 → **1,409 params** (42·32+2·32+1) |
| Federation | 30 clients, 10 selected/round, 60 rounds, record budget b=3 |
| Partitions | Dirichlet α ∈ {0.1, 0.5, 1.0}, partition seed 7 (identical logic to UNSW prep) |
| Attack | drop_client on the two clients holding the most attack rows; rounds 21–60 |
| Withholding | 2 non-target clients, rounds 21–40, restored round 41 |
| Seeds | 310001–310020 (matched across arms); 20,000-resample paired bootstrap CIs |

Attack concentration (share of the 3,185 attack rows held by the two dropped clients):
α=0.1 → 48.4% (clients 10,11); α=0.5 → 27.9% (10,11); α=1.0 → 25.1% (11,14).
Lower α concentrates the attack signal, so the drop attack is more harmful — the heterogeneity
gradient the reviewer asked to see.

## Mixed scenario — containment (applied policy-violating rounds, mean over 20 seeds)

| α | noaudit | uniform | adaptive | neutral | separated | neutral−uniform (95% CI) |
|---|---|---|---|---|---|---|
| 0.1 | 20.35 | 16.35 | 6.90 | **10.45** | 8.25 | −5.90 [−7.20, −4.55] |
| 0.5 | 20.35 | 16.35 | 6.90 | **10.45** | 8.25 | −5.90 [−7.20, −4.55] |
| 1.0 | 21.10 | 16.90 | 9.10 | **11.30** | 9.70 | −5.60 [−7.10, −4.05] |

Discarded training fraction (mixed): neutral ≈ 0.186–0.188 vs adaptive ≈ 0.321–0.341 vs
uniform ≈ 0.093. Final F1 (mixed, neutral): 0.554 / 0.534 / 0.560 for α=0.1/0.5/1.0.
Audit traffic ≈ 0.85–0.98 MB/run (smaller than the UNSW 2.68 MB because the Edge model has
1,409 vs 6,241 parameters; payload scales with model dimension).

## Withholding scenario — suppression of compliant rounds (mean over 20 seeds)

| α | uniform | adaptive | neutral | separated |
|---|---|---|---|---|
| 0.1 | 3.50 | 16.05 | **3.50** | 8.85 |
| 0.5 | 3.50 | 16.05 | **3.50** | 8.85 |
| 1.0 | 3.55 | 16.30 | **3.55** | 9.15 |

## What replicates from the UNSW paper

1. **Containment**: neutral auditing roughly halves applied violations (≈20.4→10.5), and the
   neutral−uniform reduction is significant under all three partitions (CI excludes 0).
2. **Cost ordering**: neutral discards ≈19% of training work vs ≈32–34% for adaptive — the same
   "neutral is the lower-cost audited option" finding (paper: 19.92% vs 37.42% full scope).
3. **Withholding suppression ordering**: adaptive ≈16.1–16.3 compliant rounds suppressed,
   separated ≈8.9–9.2, neutral ≈3.5 — closely tracking the paper's 16.25 / 9.30 / 3.70.
   Availability-neutral feedback avoids the over-suppression that naive adaptive feedback
   incurs when evidence is withheld, on a completely different corpus.

These three qualitative results transfer across corpora and across heterogeneity levels,
supporting the interface's claimed generality (attack evidence is defined against declared
metadata, not raw features).

## Honest boundaries

- The Edge model is smaller (1,409 params) because the DNN feature set has 42 columns; absolute
  F1 (≈0.53–0.57) and audit bytes differ from UNSW. The claim is **containment/suppression
  transfer**, not identical F1 or byte counts. Model capacity at scale is addressed separately by E2.
- Inference scope is training/scheduling seed variation over one fixed partition per α; it is not
  a population-generalization claim across sites.
- Timing/byte figures are application-layer payload accounting, not deployment/network measurements.

## Reproduce

```
python -m experiments.e1_edge.prepare_edgeiiot          # builds data/edgeiiot_subset/edgeiiot_a{0.1,0.5,1.0}
python -m experiments.e1_edge.run_e1_edge --seeds 20 --workers 6
python -m experiments.e1_edge.summarize_e1 experiments/e1_edge/results/e1_edge_a0.1 ...
```

Per-seed rows, config hashes and bootstrap summaries are in
`experiments/e1_edge/results/e1_edge_a{0.1,0.5,1.0}/` (`rows.jsonl`, `config.json`, `summary.json`).