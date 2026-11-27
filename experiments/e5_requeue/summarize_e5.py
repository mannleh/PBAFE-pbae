# -*- coding: utf-8 -*-
import json
p = r".\experiments\e5_requeue\results\summary.json"
s = json.load(open(p, encoding="utf-8"))
K = ("applied_violating_rounds", "compliant_rounds_retained", "discarded_steps_fraction",
     "discarded_compliant_steps", "f1", "audit_bytes", "discarded_training_steps",
     "requeued", "success", "failed", "censored", "slots_forced", "pending_end")
for sc in ("mixed_recovery", "withholding_recovery"):
    print("==", sc)
    for arm in ("neutral", "separated", "adaptive", "neutral_requeue", "separated_requeue"):
        m = s["means"][f"{sc}/{arm}"]
        vals = []
        for k in K:
            v = m[k]
            vals.append(f"{k}={v['mean']:.3f}" if isinstance(v, dict) and "mean" in v else f"{k}={v}")
        print(" ", arm, " ".join(vals))
    print("  delay:", {a: s["means"][f"{sc}/{a}"]["post_restore_first_apply_delay"]["conditional_mean"] for a in ("neutral","neutral_requeue","separated","separated_requeue")})
print("\npaired")
for k, v in s["paired"].items():
    print(k)
    for m, d in v.items():
        print(f"   {m}: {d['mean']:+.4f} [{d['ci97_5'][0]:+.4f},{d['ci97_5'][1]:+.4f}]")
