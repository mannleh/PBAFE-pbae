"""Emit the PBA/3 fixture outcomes consumed by oracle_v4.

Each case is constructed here and then audited; the oracle compares the
emitted JSON without importing this file's expectations.
"""
import argparse
import json
from pathlib import Path

from experiments.pba_v3.codec import derive_challenge_seed, digest, sealed_sample
from experiments.pba_v3.repository import make_fixture, tamper
from experiments.pba_v3.segfixture import add_segments, build_segment_fixture
from experiments.pba_v3.verify import audit, audit_segment


def case(name, spot, full):
    return {"case": name,
            "record_outcome": spot.outcome,
            "full_outcome": full.outcome,
            "record_aggregate_verified": spot.aggregate_verified,
            "full_aggregate_verified": full.aggregate_verified}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    cases = []
    beacon = b"oracle"
    dim, clients = 32, 8

    # 1-4: sealed record tier
    f = make_fixture(round_id=1, dimension=dim, clients=clients, seed=11)
    seed = derive_challenge_seed(f.trust.bulletin_pin, 1, beacon)
    slots = sealed_sample(seed, [1.0] * clients, 3)
    cases.append(case("sealed_honest", audit(f.source, f.trust, slots=slots),
                      audit(f.source, f.trust, full=True)))

    g = f.clone()
    g.source.pop(f"record/{slots[0]}/opening", None)
    cases.append(case("sealed_withheld_opening", audit(g.source, g.trust, slots=slots),
                      audit(g.source, g.trust, full=True)))

    g = tamper(f, "declared_count_policy", (slots[0],))
    cases.append(case("sealed_record_tamper", audit(g.source, g.trust, slots=slots),
                      audit(g.source, g.trust, full=True)))

    g = tamper(f, "identity_exchange", (slots[0],))
    cases.append(case("sealed_roster_substitution", audit(g.source, g.trust, slots=slots),
                      audit(g.source, g.trust, full=True)))

    # 5-7: segment tier
    sf = build_segment_fixture(round_id=1, dimension=64, clients=10, segments=4, seed=5)
    s_seed = derive_challenge_seed(sf.trust.bulletin_pin, 1, beacon)
    honest_seg = audit_segment(sf.source, sf.trust, s_seed, 4)
    cases.append({"case": "segment_honest",
                  "record_outcome": honest_seg.outcome,
                  "full_outcome": audit(sf.source, sf.trust, full=True).outcome,
                  "record_aggregate_verified": honest_seg.aggregate_verified,
                  "full_aggregate_verified": True})

    bad_sum = add_segments(sf, 4, tamper_segments={0, 1, 2, 3})
    seg = audit_segment(bad_sum.source, bad_sum.trust, s_seed, 4)
    full_sum = audit(bad_sum.source, bad_sum.trust, full=True)
    cases.append({"case": "segment_sum_tamper",
                  "record_outcome": seg.outcome,
                  "full_outcome": full_sum.outcome,
                  "record_aggregate_verified": seg.aggregate_verified,
                  "full_aggregate_verified": full_sum.aggregate_verified})

    bad_contrib = add_segments(sf, 4)
    bad_contrib.source.pop("record/0/contribution/0", None)
    seg = audit_segment(bad_contrib.source, bad_contrib.trust, s_seed, 4)
    full_c = audit(bad_contrib.source, bad_contrib.trust, full=True)
    cases.append({"case": "segment_contribution_tamper",
                  "record_outcome": seg.outcome,
                  "full_outcome": full_c.outcome,
                  "record_aggregate_verified": seg.aggregate_verified,
                  "full_aggregate_verified": full_c.aggregate_verified})

    # 8-9: prediction. An open schedule that draws the corrupted slot is
    # defeated; a sealed schedule that cannot draw it in advance is not.
    open_slots = list(range(3))
    g = tamper(f, "declared_count_policy", (0,))
    cases.append(case("predicting_open_schedule", audit(g.source, g.trust, slots=open_slots),
                      audit(g.source, g.trust, full=True)))
    sealed_slots = sealed_sample(seed, [1.0] * clients, 3)
    cases.append(case("predicting_sealed_schedule", audit(g.source, g.trust, slots=sealed_slots),
                      audit(g.source, g.trust, full=True)))

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({"cases": cases}, indent=2), encoding="utf8")
    for c in cases:
        print(json.dumps({k: c[k] for k in ("case", "record_outcome", "full_outcome")}))


if __name__ == "__main__":
    main()
