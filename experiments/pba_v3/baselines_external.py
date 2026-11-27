"""External scheduling baselines (P3.5).

Only the placement policy of each work is reproduced, never its cryptography.
The point is to put the auditor's own scheduler on the same axis as published
selection ideas under an identical budget.

prozkfl_style      reputation-weighted choice where the randomness is derived
                  from an external beacon (verifiable randomness), matching the
                  published emphasis on unpredictable but reproducible sampling
hiaudit_style      alternating audit targets: even rounds audit aggregate
                  level evidence, odd rounds audit record level evidence
"""
import numpy as np


def prozkfl_style(round_id, clients, budget, rng, reputation, seed_hex):
    """Reputation-weighted, beacon-derived selection.

    ``reputation`` is the auditor's prior on each slot. The beacon makes the
    draw reproducible and unpredictable before evidence is served, which is the
    property this baseline is included to test.
    """
    from experiments.pba_v3.codec import sealed_sample
    w = np.asarray(reputation, dtype=float)
    if w.sum() <= 0:
        w = np.ones(clients)
    return sealed_sample(seed_hex, w, budget)


def hiaudit_style(round_id, clients, budget, rng, reputation):
    """Alternate between aggregate-level and record-level inspection.

    On record rounds the sample follows the caller's reputation ranking; on
    aggregate rounds every accepted update is read, which is the tier this
    baseline treats as its 'model audit'.
    """
    if round_id % 2 == 0:
        return "full", list(range(clients))
    order = np.argsort(-np.asarray(reputation, dtype=float))
    return "spot", sorted(map(int, order[:budget]))
