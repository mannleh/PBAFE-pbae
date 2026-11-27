# Edge-IIoTset model-capacity stress test

Low-capacity model: 6249 parameters; high-capacity model: 49941 parameters.

Paired cells per width: 9; runs: 1800.

| contrast | mean | 95% cluster-bootstrap CI |
|---|---:|---:|
| α=0.5 high_minus_low_neutral_applied | 0.0000 | [0.0000, 0.0000] |
| α=0.5 high_minus_low_neutral_f1 | 0.0177 | [0.0113, 0.0271] |
| α=0.5 high_minus_low_neutral_discard | 0.0000 | [0.0000, 0.0000] |
| α=0.5 high_minus_low_neutral_audit_bytes | 16603020.0000 | [16253484.0000, 16952556.0000] |
| α=0.5 high_neutral_minus_uniform_applied | -7.7667 | [-8.4000, -7.4000] |
| α=0.5 high_neutral_minus_noudit_f1 | -0.0120 | [-0.0162, -0.0076] |
| α=0.5 high_neutral_minus_adaptive_compliant | -4.8667 | [-5.3000, -4.0000] |
