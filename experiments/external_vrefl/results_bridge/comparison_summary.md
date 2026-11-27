# VREFL verification-core comparison

VREFL runs: 40; PBA/3 bridge runs: 240.

| scenario | method | applied violations | compliant retained | discard fraction | F1 | audit MB | audit CPU s |
|---|---:|---:|---:|---:|---:|---:|---:|
| mixed_recovery | noaudit | 22.350 | 0.000 | 0.0000 | 0.7297 | 0.000 | 0.000 |
| mixed_recovery | uniform | 17.950 | 1.750 | 0.1025 | 0.7277 | 3.156 | 0.836 |
| mixed_recovery | adaptive | 8.300 | 7.050 | 0.3517 | 0.7156 | 2.583 | 0.780 |
| mixed_recovery | neutral | 10.100 | 1.500 | 0.2292 | 0.7190 | 2.691 | 0.787 |
| mixed_recovery | separated | 8.300 | 3.850 | 0.2983 | 0.7186 | 2.653 | 0.802 |
| mixed_recovery | pba_full | 0.000 | 8.750 | 0.5183 | 0.7121 | 32.039 | 18.605 |
| mixed_recovery | vrefl_full | 16.100 | 5.650 | 0.1983 | 0.7273 | 26.060 | 80.534 |
| withholding_recovery | noaudit | 0.000 | 0.000 | 0.0000 | 0.7511 | 0.000 | 0.000 |
| withholding_recovery | uniform | 0.000 | 3.700 | 0.0617 | 0.7499 | 3.289 | 0.873 |
| withholding_recovery | adaptive | 0.000 | 16.250 | 0.2708 | 0.7485 | 2.969 | 0.821 |
| withholding_recovery | neutral | 0.000 | 3.700 | 0.0617 | 0.7499 | 3.289 | 0.859 |
| withholding_recovery | separated | 0.000 | 9.300 | 0.1550 | 0.7502 | 3.198 | 0.831 |
| withholding_recovery | pba_full | 0.000 | 20.000 | 0.3333 | 0.7461 | 33.882 | 22.098 |
| withholding_recovery | vrefl_full | 0.000 | 11.900 | 0.1983 | 0.7491 | 27.242 | 83.892 |

## Paired VREFL minus PBA/3 contrasts

| scenario | contrast | mean | 95% CI |
|---|---|---:|---:|
| mixed_recovery | vrefl_minus_noaudit/applied_violating_rounds | -6.2500 | [-7.0500, -5.4000] |
| mixed_recovery | vrefl_minus_noaudit/compliant_rounds_retained | 5.6500 | [4.9000, 6.4500] |
| mixed_recovery | vrefl_minus_noaudit/discarded_steps_fraction | 0.1983 | [0.1825, 0.2133] |
| mixed_recovery | vrefl_minus_noaudit/f1 | -0.0024 | [-0.0068, 0.0017] |
| mixed_recovery | vrefl_minus_noaudit/audit_total_bytes | 26059582.2000 | [25575961.0750, 26548259.0650] |
| mixed_recovery | vrefl_minus_uniform/applied_violating_rounds | -1.8500 | [-2.7000, -1.0000] |
| mixed_recovery | vrefl_minus_uniform/compliant_rounds_retained | 3.9000 | [3.1000, 4.9000] |
| mixed_recovery | vrefl_minus_uniform/discarded_steps_fraction | 0.0958 | [0.0800, 0.1117] |
| mixed_recovery | vrefl_minus_uniform/f1 | -0.0004 | [-0.0040, 0.0028] |
| mixed_recovery | vrefl_minus_uniform/audit_total_bytes | 22903421.4000 | [22402064.1363, 23401769.4213] |
| mixed_recovery | vrefl_minus_adaptive/applied_violating_rounds | 7.8000 | [5.9500, 9.8000] |
| mixed_recovery | vrefl_minus_adaptive/compliant_rounds_retained | -1.4000 | [-2.5500, -0.1000] |
| mixed_recovery | vrefl_minus_adaptive/discarded_steps_fraction | -0.1533 | [-0.1933, -0.1150] |
| mixed_recovery | vrefl_minus_adaptive/f1 | 0.0117 | [0.0003, 0.0247] |
| mixed_recovery | vrefl_minus_adaptive/audit_total_bytes | 23476105.9000 | [22963578.8212, 23994399.2875] |
| mixed_recovery | vrefl_minus_neutral/applied_violating_rounds | 6.0000 | [3.3500, 8.8500] |
| mixed_recovery | vrefl_minus_neutral/compliant_rounds_retained | 4.1500 | [3.3500, 5.1000] |
| mixed_recovery | vrefl_minus_neutral/discarded_steps_fraction | -0.0308 | [-0.0792, 0.0133] |
| mixed_recovery | vrefl_minus_neutral/f1 | 0.0083 | [-0.0037, 0.0256] |
| mixed_recovery | vrefl_minus_neutral/audit_total_bytes | 23368637.5000 | [22851260.7600, 23886170.6250] |
| mixed_recovery | vrefl_minus_separated/applied_violating_rounds | 7.8000 | [5.4000, 10.2500] |
| mixed_recovery | vrefl_minus_separated/compliant_rounds_retained | 1.8000 | [0.8000, 2.9000] |
| mixed_recovery | vrefl_minus_separated/discarded_steps_fraction | -0.1000 | [-0.1450, -0.0567] |
| mixed_recovery | vrefl_minus_separated/f1 | 0.0087 | [-0.0042, 0.0268] |
| mixed_recovery | vrefl_minus_separated/audit_total_bytes | 23406883.7000 | [22891819.4162, 23921836.1713] |
| mixed_recovery | vrefl_minus_pba_full/applied_violating_rounds | 16.1000 | [14.8500, 17.3500] |
| mixed_recovery | vrefl_minus_pba_full/compliant_rounds_retained | -3.1000 | [-3.6500, -2.5500] |
| mixed_recovery | vrefl_minus_pba_full/discarded_steps_fraction | -0.3200 | [-0.3450, -0.2958] |
| mixed_recovery | vrefl_minus_pba_full/f1 | 0.0152 | [-0.0029, 0.0367] |
| mixed_recovery | vrefl_minus_pba_full/audit_total_bytes | -5979174.8500 | [-6513493.5850, -5447392.9550] |
| withholding_recovery | vrefl_minus_noaudit/applied_violating_rounds | 0.0000 | [0.0000, 0.0000] |
| withholding_recovery | vrefl_minus_noaudit/compliant_rounds_retained | 11.9000 | [10.9500, 12.8000] |
| withholding_recovery | vrefl_minus_noaudit/discarded_steps_fraction | 0.1983 | [0.1825, 0.2133] |
| withholding_recovery | vrefl_minus_noaudit/f1 | -0.0020 | [-0.0063, 0.0023] |
| withholding_recovery | vrefl_minus_noaudit/audit_total_bytes | 27242106.6500 | [26682521.8163, 27809290.7238] |
| withholding_recovery | vrefl_minus_uniform/applied_violating_rounds | 0.0000 | [0.0000, 0.0000] |
| withholding_recovery | vrefl_minus_uniform/compliant_rounds_retained | 8.2000 | [7.2000, 9.2000] |
| withholding_recovery | vrefl_minus_uniform/discarded_steps_fraction | 0.1367 | [0.1200, 0.1533] |
| withholding_recovery | vrefl_minus_uniform/f1 | -0.0008 | [-0.0036, 0.0027] |
| withholding_recovery | vrefl_minus_uniform/audit_total_bytes | 23953350.5000 | [23366433.0538, 24533245.8500] |
| withholding_recovery | vrefl_minus_adaptive/applied_violating_rounds | 0.0000 | [0.0000, 0.0000] |
| withholding_recovery | vrefl_minus_adaptive/compliant_rounds_retained | -4.3500 | [-6.2000, -2.1500] |
| withholding_recovery | vrefl_minus_adaptive/discarded_steps_fraction | -0.0725 | [-0.1033, -0.0358] |
| withholding_recovery | vrefl_minus_adaptive/f1 | 0.0006 | [-0.0025, 0.0038] |
| withholding_recovery | vrefl_minus_adaptive/audit_total_bytes | 24273533.4000 | [23673361.0000, 24873504.2062] |
| withholding_recovery | vrefl_minus_neutral/applied_violating_rounds | 0.0000 | [0.0000, 0.0000] |
| withholding_recovery | vrefl_minus_neutral/compliant_rounds_retained | 8.2000 | [7.2000, 9.2000] |
| withholding_recovery | vrefl_minus_neutral/discarded_steps_fraction | 0.1367 | [0.1200, 0.1533] |
| withholding_recovery | vrefl_minus_neutral/f1 | -0.0008 | [-0.0036, 0.0027] |
| withholding_recovery | vrefl_minus_neutral/audit_total_bytes | 23953350.5000 | [23366433.0538, 24533245.8500] |
| withholding_recovery | vrefl_minus_separated/applied_violating_rounds | 0.0000 | [0.0000, 0.0000] |
| withholding_recovery | vrefl_minus_separated/compliant_rounds_retained | 2.6000 | [0.9500, 4.3000] |
| withholding_recovery | vrefl_minus_separated/discarded_steps_fraction | 0.0433 | [0.0158, 0.0717] |
| withholding_recovery | vrefl_minus_separated/f1 | -0.0011 | [-0.0037, 0.0019] |
| withholding_recovery | vrefl_minus_separated/audit_total_bytes | 24044214.3500 | [23461379.5875, 24623589.0250] |
| withholding_recovery | vrefl_minus_pba_full/applied_violating_rounds | 0.0000 | [0.0000, 0.0000] |
| withholding_recovery | vrefl_minus_pba_full/compliant_rounds_retained | -8.1000 | [-9.0500, -7.2000] |
| withholding_recovery | vrefl_minus_pba_full/discarded_steps_fraction | -0.1350 | [-0.1508, -0.1200] |
| withholding_recovery | vrefl_minus_pba_full/f1 | 0.0030 | [-0.0012, 0.0074] |
| withholding_recovery | vrefl_minus_pba_full/audit_total_bytes | -6639555.1500 | [-7182936.5038, -6095706.3150] |
