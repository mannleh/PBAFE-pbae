# E1-L summary

Cells: 75; runs: 7500; bootstrap resamples: 20000.

Intervals use a two-way cluster bootstrap over sample-seed x partition-seed cells.

| alpha | arm | applied violations | F1 | discard fraction | audit MB |
|---|---:|---:|---:|---:|---:|
| 0.1 | noaudit | 22.840 | 0.5030 | 0.0000 | 0.000 |
| 0.1 | uniform | 18.200 | 0.5043 | 0.1007 | 3.101 |
| 0.1 | adaptive | 8.380 | 0.5113 | 0.3343 | 2.553 |
| 0.1 | neutral | 10.180 | 0.5112 | 0.2290 | 2.611 |
| 0.1 | separated | 8.740 | 0.5123 | 0.2860 | 2.543 |
| 0.5 | noaudit | 23.120 | 0.6149 | 0.0000 | 0.000 |
| 0.5 | uniform | 18.300 | 0.6129 | 0.1043 | 3.090 |
| 0.5 | adaptive | 8.760 | 0.5996 | 0.3377 | 2.550 |
| 0.5 | neutral | 10.080 | 0.6078 | 0.2383 | 2.598 |
| 0.5 | separated | 9.240 | 0.6039 | 0.2890 | 2.566 |
| 1.0 | noaudit | 22.520 | 0.6079 | 0.0000 | 0.000 |
| 1.0 | uniform | 17.940 | 0.6072 | 0.1000 | 3.107 |
| 1.0 | adaptive | 9.340 | 0.6030 | 0.3173 | 2.615 |
| 1.0 | neutral | 10.700 | 0.6053 | 0.2183 | 2.666 |
| 1.0 | separated | 9.700 | 0.6045 | 0.2763 | 2.641 |

## Cluster-bootstrap contrasts

| alpha | contrast | mean | 95% CI |
|---|---|---:|---:|
| 0.1 | mixed_neutral_minus_uniform_applied | -8.0200 | [-9.2800, -6.7600] |
| 0.1 | mixed_neutral_minus_noudit_f1 | 0.0081 | [-0.0148, 0.0471] |
| 0.1 | mixed_neutral_minus_adaptive_compliant | -4.5200 | [-5.3000, -3.8600] |
| 0.1 | withholding_neutral_minus_adaptive_compliant | -10.5600 | [-11.6200, -9.6800] |
| 0.5 | mixed_neutral_minus_uniform_applied | -8.2200 | [-9.3000, -7.1400] |
| 0.5 | mixed_neutral_minus_noudit_f1 | -0.0071 | [-0.0115, -0.0030] |
| 0.5 | mixed_neutral_minus_adaptive_compliant | -4.6400 | [-5.4400, -4.0000] |
| 0.5 | withholding_neutral_minus_adaptive_compliant | -10.5200 | [-11.3000, -9.7000] |
| 1.0 | mixed_neutral_minus_uniform_applied | -7.2400 | [-8.3400, -6.1400] |
| 1.0 | mixed_neutral_minus_noudit_f1 | -0.0027 | [-0.0041, -0.0013] |
| 1.0 | mixed_neutral_minus_adaptive_compliant | -4.5800 | [-4.9400, -4.2400] |
| 1.0 | withholding_neutral_minus_adaptive_compliant | -10.6800 | [-11.4000, -10.0200] |
