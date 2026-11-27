"""P3 pilot: does excluding the attack-heavy client produce a measurable F1 loss?

Kept as a standalone probe so the consequence runner only changes once the
manipulation is known to have a real effect.
"""
import json

import numpy as np

from experiments.pba_v3 import flcore

z = np.load("data/unsw_official_subset_v3/unsw_subset.npz")
Xtr, ytr = z["X_train"], z["y_train"]
Xte, yte = z["X_test"], z["y_test"]
cidx = json.load(open("data/unsw_official_subset_v3/client_indices.json", encoding="utf8"))
d, h, seed = Xtr.shape[1], 32, 101


def run(drop=False, target=15):
    rng = np.random.default_rng(seed)
    w = np.concatenate([rng.normal(0, .05, d * h), np.zeros(h), rng.normal(0, .05, h), np.zeros(1)])
    cw = {0: len(ytr) / (2 * max(1, int((ytr == 0).sum()))),
          1: len(ytr) / (2 * max(1, int((ytr == 1).sum())))}
    sched = [sorted(map(int, rng.choice(len(cidx), 10, replace=False))) for _ in range(60)]
    traj = []
    for r, chosen in enumerate(sched):
        if drop and r >= 20:
            chosen = [c for c in chosen if c != target]
            if not chosen:
                chosen = [0]
        vecs, counts = [], []
        for ci in chosen:
            ids = np.asarray(cidx[ci], dtype=int)
            local_rng = np.random.default_rng(np.random.SeedSequence([seed, r, ci, 71]))
            vecs.append(flcore.local_update(w, Xtr[ids], ytr[ids], h, local_rng, lr=.03, class_weights=cw))
            counts.append(len(ids))
        w = w + flcore.server_aggregate(vecs, counts) / 1e6
        if r % 10 == 9:
            traj.append(round(flcore.metrics(yte, (flcore.predict(w, Xte, h) >= .5).astype(int))["f1"], 4))
    return flcore.metrics(yte, (flcore.predict(w, Xte, h) >= .5).astype(int))["f1"], traj


for drop in (False, True):
    f, t = run(drop)
    print("drop15=%s finalF1=%.4f traj=%s" % (drop, f, t))
