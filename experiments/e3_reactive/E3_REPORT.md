# E3 — Adjudicated reactive opponent (target transfer + frequency-triggered withholding)

Status: **complete** — 100 matched seeds (230001–230100), 60 rounds, b = 3, four schedulers, ε ∈ {0.0, 0.3, 0.7, 1.0}; 288,000 independent semantic checks passed.
Script: `experiments/e3_reactive/run_e3.py` → `results/rows.json`, `results/summary.json`.

## 1. Threat model actually implemented

- The adversary observes the **audit slots of the previous round** (challenge requests are public) and, with probability ε, relocates its two tampered clients into the complement of that set; otherwise it keeps them (persistent tamper epoch).
- Independently, the two **most frequently sampled** clients lose their opening (withholding), so any scheduler that returns to the same slot pays for it in evidence. Withholding is thus frequency-triggered, not random.
- ε = 0.0 is the fixed trajectory; it is re-run inside this harness as the matched reference (its absolute value differs slightly from the standalone scheduling table because the seed block and the withholding rule differ — all comparisons below are within-experiment).

## 2. Results (mean over 100 seeds)

| ε | uniform | adaptive | neutral | separated |
|---|---|---|---|---|
| 0.0 TDR | 0.1950 | 0.8873 | **0.9296** | 0.9179 |
| 0.3 TDR | 0.1983 | 0.1521 | 0.2327 | **0.3340** |
| 0.7 TDR | **0.1938** | 0.1048 | 0.1640 | 0.2065 |
| 1.0 TDR | **0.1908** | 0.0819 | 0.1356 | 0.1627 |
| 0.0 bytes (KB) | 695 | 478 | 548 | 518 |
| 1.0 bytes (KB) | 695 | 547 | 612 | 656 |

Degradation relative to the fixed trajectory (paired by seed, 97.5% CI):

| ε | uniform | adaptive | neutral | separated |
|---|---|---|---|---|
| 0.3 | +0.003 [−0.014, +0.021] | −0.735 [−0.769, −0.700] | −0.697 [−0.721, −0.672] | −0.584 [−0.613, −0.554] |
| 0.7 | −0.001 [−0.017, +0.015] | −0.782 [−0.814, −0.746] | −0.766 [−0.785, −0.745] | −0.711 [−0.736, −0.684] |
| 1.0 | −0.004 [−0.022, +0.014] | −0.805 [−0.835, −0.772] | −0.794 [−0.812, −0.774] | −0.755 [−0.778, −0.730] |

## 3. Reading

1. **Concentration is what relocation punishes.** Under a fixed trajectory, the three evidence-based arms sit at 0.89–0.93 and uniform at 0.195; under per-round relocation they collapse to 0.08–0.33, while uniform is unchanged (its 0.19 does not depend on where the target was last round). The collapse is largest for adaptive (−0.805) and neutral (−0.794), smallest for separated (−0.755) — separation degrades most gracefully because it never puts its whole budget on the current suspect.
2. **The residual is coverage, not inference.** When the target leaves the audited set, the next target location is independent of everything the auditor observed, so outcome-only feedback cannot be converted into predictive advantage. With 2 targets inside the 27-slot complement of the last selection and b = 3, the geometric per-round hit ceiling for a coverage sampler is \(1-\binom{25}{3}/\binom{27}{3}=0.214\); uniform measures 0.191, i.e. it operates at 89% of the ceiling. Any evidence-based arm above that ceiling is living on the ε=0 persistence, not on leaked information.
3. **This is a boundary, not a refutation.** The paper's operating assumption is that tamper epochs persist long enough for evidence to accumulate (the attack window is a sustained epoch, not per-round camouflage). E3 measures exactly how much performance depends on that assumption and supplies the floor that any claim must be compared against. It also independently justifies keeping **separated** as the conservative arm: at ε = 1.0 it retains 0.163 versus neutral 0.136 and adaptive 0.082.
4. **No hidden benefit is claimed.** In this reactive regime no evidence-based arm beats plain uniform coverage; the honest statement is that the framework's gain is confined to persistent-target epochs, and the letter should say so explicitly rather than imply universal robustness.

## 4. What goes into the manuscript

- New subsection 7.x: "Reactive target relocation: where the advantage ends", with the ε ladder table and the degradation CIs.
- One sentence in the limitations: target persistence is a precondition; under per-round relocation the achievable TDR is coverage-bounded (≈ b/N·(N−k)/(N−b) envelope), and separated is the preferred arm.
- The 21.4% geometric ceiling is derived in one line and is checkable by the reviewer.
