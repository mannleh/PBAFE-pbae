"""Federated learning core, matching the released PBA/2 integration exactly.

``run_fl_v2.py`` uses a one-hidden-layer ReLU network with integer fixed-point
updates. A different activation (tanh) in a consequence experiment would make
the two lines of work incomparable, so the model code is reproduced here rather
than re-derived. Only the metric helpers are local, so this module does not
depend on scikit-learn.
"""
import numpy as np

from experiments.pba_v3.codec import MAX_COORD, SCALE


def sigmoid(z):
    return 1 / (1 + np.exp(-np.clip(z, -30, 30)))


def unpack(w, d, h):
    a = d * h
    return w[:a].reshape(d, h), w[a:a + h], w[a + h:a + 2 * h], w[-1]


def predict(w, X, h):
    W, b, v, c = unpack(w, X.shape[1], h)
    return sigmoid(np.maximum(X @ W + b, 0) @ v + c)


def local_update(w, X, y, h, rng, batch=128, lr=.03, class_weights=None):
    idx = rng.choice(len(y), min(batch, len(y)), replace=False)
    X, y = X[idx], y[idx]
    W, b, v, c = unpack(w, X.shape[1], h)
    z = X @ W + b
    hidden = np.maximum(z, 0)
    e = sigmoid(hidden @ v + c) - y
    if class_weights is not None:
        e = e * np.asarray([class_weights[int(label)] for label in y])
    e = e / len(y)
    dh = (e[:, None] * v[None, :]) * (z > 0)
    grad = np.concatenate([(X.T @ dh).ravel(), dh.sum(axis=0), hidden.T @ e, [e.sum()]])
    update = np.rint(-lr * grad * SCALE).astype(np.int64)
    if np.max(np.abs(update)) > MAX_COORD:
        raise ValueError("fixed-point update bound")
    return update


def server_aggregate(vectors, counts):
    vectors = np.asarray(vectors, dtype=np.int64)
    counts = np.asarray(counts, dtype=np.int64)
    denominator = int(counts.sum())
    if int(np.max(np.abs(vectors))) * denominator > np.iinfo(np.int64).max:
        raise OverflowError("server numerator exceeds int64")
    numerator = (vectors * counts[:, None]).sum(axis=0, dtype=np.int64)
    q, r = np.divmod(np.abs(numerator), denominator)
    q = q + ((2 * r > denominator) | ((2 * r == denominator) & ((q % 2) == 1)))
    return np.where(numerator < 0, -q, q).astype(np.int64)


def metrics(y, pred):
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    tnr = tn / (tn + fp) if tn + fp else 0.0
    return {"f1": f1, "precision": prec, "recall": rec,
            "balanced_accuracy": (rec + tnr) / 2}
