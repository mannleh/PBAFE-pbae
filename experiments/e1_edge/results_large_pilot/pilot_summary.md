# E1-L pilot summary

Cells: 12; runs: 600; bootstrap resamples: 20000.

Pilot intervals are descriptive: only four sample x partition cells per alpha.

| alpha | arm | applied violations | F1 | discard fraction | audit MB |
|---|---:|---:|---:|---:|---:|
| 0.1 | noaudit | 23.000 | 0.3743 | 0.0000 | 0.000 |
| 0.1 | uniform | 18.700 | 0.3965 | 0.1033 | 3.221 |
| 0.1 | adaptive | 8.000 | 0.5395 | 0.3517 | 2.596 |
| 0.1 | neutral | 9.200 | 0.4783 | 0.2583 | 2.690 |
| 0.1 | separated | 8.000 | 0.5049 | 0.3050 | 2.639 |
| 0.5 | noaudit | 21.600 | 0.6265 | 0.0000 | 0.000 |
| 0.5 | uniform | 18.300 | 0.6231 | 0.0817 | 3.281 |
| 0.5 | adaptive | 9.800 | 0.6106 | 0.3067 | 2.746 |
| 0.5 | neutral | 13.100 | 0.6197 | 0.1650 | 2.950 |
| 0.5 | separated | 11.100 | 0.6148 | 0.2283 | 2.884 |
| 1.0 | noaudit | 22.800 | 0.6049 | 0.0000 | 0.000 |
| 1.0 | uniform | 17.800 | 0.5995 | 0.1017 | 3.216 |
| 1.0 | adaptive | 6.700 | 0.5783 | 0.3817 | 2.452 |
| 1.0 | neutral | 8.400 | 0.5889 | 0.2567 | 2.690 |
| 1.0 | separated | 8.600 | 0.5879 | 0.2917 | 2.695 |

## Cluster-bootstrap contrasts

| alpha | contrast | mean | 95% CI |
|---|---|---:|---:|
| 0.1 | mixed_neutral_minus_uniform_applied | -9.5000 | [-11.6000, -7.4000] |
| 0.1 | mixed_neutral_minus_noudit_f1 | 0.1040 | [-0.0239, 0.2365] |
| 0.1 | mixed_neutral_minus_adaptive_compliant | -4.4000 | [-5.0000, -3.8000] |
| 0.1 | withholding_neutral_minus_adaptive_compliant | -13.0000 | [-13.0000, -13.0000] |
| 0.5 | mixed_neutral_minus_uniform_applied | -5.2000 | [-7.4000, -3.0000] |
| 0.5 | mixed_neutral_minus_noudit_f1 | -0.0068 | [-0.0069, -0.0067] |
| 0.5 | mixed_neutral_minus_adaptive_compliant | -5.2000 | [-6.6000, -3.8000] |
| 0.5 | withholding_neutral_minus_adaptive_compliant | -13.2000 | [-13.4000, -13.0000] |
| 1.0 | mixed_neutral_minus_uniform_applied | -9.4000 | [-11.6000, -7.2000] |
| 1.0 | mixed_neutral_minus_noudit_f1 | -0.0159 | [-0.0194, -0.0126] |
| 1.0 | mixed_neutral_minus_adaptive_compliant | -5.8000 | [-6.0000, -5.6000] |
| 1.0 | withholding_neutral_minus_adaptive_compliant | -13.8000 | [-14.0000, -13.6000] |
