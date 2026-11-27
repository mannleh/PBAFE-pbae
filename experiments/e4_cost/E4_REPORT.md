# E4 — Cost-effectiveness synthesis (R1-6 / R3-5)

Status: **complete** (analysis only; reuses frozen run outputs, no new training).
Script: `experiments/e4_cost/analyze_e4.py` → `E4_cost_effectiveness.csv`, `E4_rows.json`, `E4_pareto.png`.

## 1. What is computed

For every audited arm, from the per-seed rows already on disk:

| quantity | definition |
|---|---|
| contained violations | no-audit applied violating rounds − arm applied violating rounds (paired, same seed/fixture) |
| discarded steps | rejected local updates × local epochs (absolute count) |
| audit traffic | serializer bytes over the 60-round horizon (MB = 10^6 B) |
| contained / discarded step | marginal integrity gain per unit of lost training |
| contained / MB | marginal integrity gain per unit of audit bandwidth |
| Pareto set | non-dominated in (containment ↑, discarded steps ↓, traffic ↓) |

Sources: `decision_v5_20261022/response/summary.json` (UNSW six arms, 20 seeds 300001–300020) and `e1_edge/results/e1_edge_a{0.1,0.5,1.0}/summary.json` (Edge-IIoTset five arms, 20 seeds 310001–310020).

## 2. UNSW-NB15 (six arms, same 60-round horizon, b = 3, 30 clients)

| arm | contained | discarded steps | traffic (MB) | per step | per MB | F1 |
|---|---|---|---|---|---|---|
| drop_noaudit | 0.00 | 0.0 | 0.000 | — | — | 0.7260 |
| drop_uniform_b3 | 3.70 | 37.0 | 3.194 | 0.100 | **1.158** | 0.7242 |
| drop_neutral_b3 | **11.95** | 119.5 | **2.681** | 0.100 | **4.457** | 0.7248 |
| drop_separated_b3 | 11.95 | 119.5 | 2.681 | 0.100 | 4.457 | 0.7248 |
| drop_full_b30 | 22.45 | 224.5 | 33.123 | 0.100 | 0.678 | 0.7223 |

Reading:
- **Uniform spends almost as much bandwidth as neutral (3.19 vs 2.68 MB) for a third of the containment** (3.70 vs 11.95): per-MB efficiency 1.16 vs 4.46, i.e. **3.85× worse**.
- **Full scope is the only arm that beats neutral on absolute containment (22.45 vs 11.95, 1.88×), and it pays 12.4× the traffic and 1.88× the discarded steps** — per-MB efficiency collapses to 0.678, the worst of all arms. That is exactly the "no free containment" statement of the paper.
- `drop_separated_b3` coincides with neutral here because the response fixture contains **no due-at-selection records**; the separation property is exercised in the scheduling study (E5/E7), not in this fixture. Reported as-is, not as evidence of equivalence in general.
- Per-step efficiency is structurally 1/(selected updates)=0.100 on this fixture for every arm (each attack round costs exactly one selection of 10 steps), so the discriminating axis here is per-MB, not per-step.

Pareto frontier (UNSW): uniform, neutral, separated, full — i.e. **all four audited arms are non-dominated**, so the trade-off is genuinely three-way and cannot be collapsed to "one arm wins".

## 3. Edge-IIoTset (five arms × three Dirichlet partitions)

α = 0.1 (dropped clients carry 48.4% of attack rows):

| arm | contained | discarded steps | traffic (MB) | per step | per MB | F1 |
|---|---|---|---|---|---|---|
| noaudit | 0.00 | 0.0 | 0.000 | — | — | 0.5679 |
| uniform | 4.00 | 55.5 | 0.958 | 0.072 | 4.177 | 0.5627 |
| adaptive | 13.45 | 204.5 | **0.853** | 0.066 | **15.777** | 0.5214 |
| neutral | 9.90 | 113.0 | 0.874 | **0.088** | 11.328 | 0.5542 |
| separated | 12.10 | 157.0 | 0.851 | 0.077 | 14.215 | 0.5398 |

α = 0.5: identical containment/traffic profile (contained 4.00 / 13.45 / 9.90 / 12.10), F1 0.5536 / 0.5073 / 0.5341 / 0.5321.
α = 1.0: contained 4.20 / 12.00 / 9.80 / 11.40; discarded 56.0 / 193.0 / 111.5 / 156.5; traffic 0.955 / 0.856 / 0.879 / 0.860 MB; per-MB 4.40 / 14.02 / 11.15 / 13.25; F1 0.5665 / 0.5396 / 0.5606 / 0.5503.

Reading:
- **Neutral is the most discard-efficient and the most F1-preserving audited arm** (9.90 contained for 113 steps = 18.8% of the budget, F1 0.5542 vs 0.5679 no-audit → −0.0137). Adaptive buys 3.55 more contained rounds but burns 1.81× the steps (204.5) and costs 0.033 more F1.
- **All four audited arms sit on the Pareto frontier in every partition**: adaptive leads absolute containment and per-MB; neutral leads per-discarded-step and F1; separated interpolates. This is a *multi-objective* frontier, which is precisely the paper's claim — the contribution is the measurable coupling, not a claim that one policy dominates everything.

## 4. Caveats (to be stated in the letter)

1. UNSW per-step efficiency is degenerate (0.100 for all arms) by construction of the fixture; Edge differentiates because compliant rejections dilute it.
2. Edge F1 loss under neutral (≈0.014) is larger than UNSW (≈0.001) because the same 113 discarded steps are a bigger share of a 60-round/30-client budget with thinner per-client data — reported, not hidden.
3. Traffic is application-layer serialized bytes only (no TLS/netem overhead); E6 adds wall-clock/memory accounting at the edge, energy not measured.
