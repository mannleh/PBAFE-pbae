# E7 — Stronger budget-aware baselines (UCB / ε-greedy)

Status: **complete** — 100 seeds (220001–220100), 7 scenarios, 6 methods, b = 3, 4,200 rows, 756,000 semantic checks.
Scripts: `experiments/e7_baselines/run_e7.py`, `summarize_e7.py` → `results/summary.json`.

## 1. What was added

Two schedulers that use the same outcome-only feedback but are stronger competitors than uniform:

- **ucb**: top-b by `risk/count + c·sqrt(log t / count)`, INCONCLUSIVE counted as 0.5 risk (same integrity semantics as adaptive, plus explicit exploration).
- **ε-greedy**: with probability 0.15 sample uniformly, otherwise top-b by risk (INCONCLUSIVE = 0.5).

The four original arms are unchanged and re-run in the same harness, so every comparison is seed-matched.

## 2. TDR (mean over 100 seeds) and audit bytes

| scenario | uniform | adaptive | neutral | separated | ucb | ε-greedy |
|---|---|---|---|---|---|---|
| integrity_only | 0.1938 / 717 KB | 0.8996 / 567 | **0.8996 / 567** | 0.8996 / 567 | 0.8404 / 572 | 0.8246 / 580 |
| mixed | 0.1938 / 694 | 0.8594 / 486 | **0.8996 / 556** | 0.8917 / 524 | 0.8206 / 545 | 0.8085 / 493 |
| recovery | 0.1938 / 706 | 0.8613 / 559 | **0.8996 / 561** | 0.8925 / 555 | 0.8206 / 561 | 0.8085 / 566 |
| moving_integrity | 0.2044 / 715 | 0.1623 / 720 | 0.1623 / 720 | 0.1623 / 720 | **0.3208 / 699** | 0.1521 / 721 |
| moving_mixed | 0.2044 / 693 | 0.1106 / 605 | 0.1623 / 711 | 0.1473 / 670 | **0.2844 / 645** | 0.1019 / 617 |

Paired against neutral (97.5% CI, 20,000 resamples):

| scenario | neutral−ucb | neutral−εgreedy |
|---|---|---|
| integrity_only | +0.0592 [+0.0317, +0.0856] | +0.0750 [+0.0438, +0.1054] |
| mixed | +0.0790 [+0.0512, +0.1056] | +0.0912 [+0.0562, +0.1269] |
| recovery | +0.0790 [+0.0512, +0.1056] | +0.0912 [+0.0562, +0.1269] |
| moving_integrity | −0.1585 [−0.1823, −0.1348] | +0.0102 [−0.0044, +0.0244] |
| moving_mixed | −0.1221 [−0.1423, −0.1017] | +0.0604 [+0.0454, +0.0750] |

## 3. Reading — and the part that must not be hidden

1. **In the stationary and recovery regimes the advantage is not a weak-baseline artifact.** Against UCB and ε-greedy, neutral still wins by +0.079/+0.091 in `mixed` and `recovery`, with CIs excluding zero, at essentially the same bandwidth (556 KB vs 545/493 KB). Both competitors treat INCONCLUSIVE exactly as neutral's integrity risk, so the gap comes from neutral's availability-neutral weighting, not from a softer adversary model.
2. **Under a moving target, UCB wins — and uses fewer bytes.** `moving_integrity`: 0.3208 vs neutral 0.1623, 699 KB vs 720 KB; `moving_mixed`: 0.2844 vs 0.1623, 645 KB vs 711 KB. This is not noise (CIs are far from zero) and it is consistent with the paper's own observation that uniform exploration beats stale concentration when targets move. UCB is, in effect, a smarter uniform sampler that stops paying for expired beliefs.
3. **Therefore the defensible claim is regime-specific.** The framework's advantage is in persistent-target epochs with adjudication; mobility is where exploration wins. E7 turns the previously implicit boundary into a measured one, and it improves the paper: a reviewer can now see exactly where the method should and should not be used. It does **not** support any claim of universal dominance, and the letter must not make one.

## 4. Into the manuscript

- Section 5.1/7.3: add UCB and ε-greedy rows to the scheduler table; one paragraph "stronger budget-aware baselines" stating the stationary gain (+0.079/+0.091) and the mobility reversal (0.3208 vs 0.1623 at lower bytes).
- Abstract/contributions: keep the stationary claim, add "regime characterization" as a contribution rather than overclaiming robustness.
