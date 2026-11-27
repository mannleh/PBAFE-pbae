# -*- coding: utf-8 -*-
"""E1 cross-dataset preparation: Edge-IIoTset (DNN-EdgeIIoT-dataset.csv).

Produces the SAME on-disk interface as the released UNSW subset
(``unsw_subset.npz`` + ``client_indices.json`` + ``dataset_manifest.json``) so the
frozen PBA/3 application runners (v5_response / v6_bridge) can be reused without
modification. The only dataset-specific quantity re-derived here is the pair of
dominant attack clients used by the drop_client attack (the UNSW release fixes
these to clients 15/13); for Edge-IIoTset they are the two clients holding the
most attack rows under each Dirichlet partition.

Preprocessing follows prepare_unsw_official.py: train-only StandardScaler fit,
inf/nan -> 0, disjoint/exhaustive Dirichlet partition over the binary label.
"""
import argparse, hashlib, json, sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, r".")
from experiments.pba_v2.prepare_unsw_official import partition  # identical partition logic

CSV = Path(r".\data\archive\Edge-IIoTset dataset\Selected dataset for ML and DL\DNN-EdgeIIoT-dataset.csv")
LABEL = "Attack_label"


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def dominant_attack_clients(y, indices, k=2):
    counts = [int((y[np.asarray(block, dtype=int)] == 1).sum()) for block in indices]
    order = sorted(range(len(indices)), key=lambda c: (-counts[c], c))
    return sorted(order[:k]), counts


def prepare(out_root, alphas=(0.1, 0.5, 1.0), clients=30, max_train=12000, max_test=4000, seed=7):
    df = pd.read_csv(CSV, low_memory=False)
    numeric = [c for c in df.select_dtypes(include=[np.number]).columns if c != LABEL]
    rng = np.random.default_rng(seed)
    perm = rng.permutation(len(df))
    tr = df.iloc[perm[:max_train]].reset_index(drop=True)
    te = df.iloc[perm[max_train:max_train + max_test]].reset_index(drop=True)
    y_train = tr[LABEL].astype(int).to_numpy()
    y_test = te[LABEL].astype(int).to_numpy()

    def clean(frame):
        x = frame[numeric].replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return x.apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(dtype=np.float64)

    scaler = StandardScaler().fit(clean(tr))
    X_train = scaler.transform(clean(tr)).astype(np.float32)
    X_test = scaler.transform(clean(te)).astype(np.float32)

    manifests = {}
    for alpha in alphas:
        indices = partition(y_train, clients, alpha, seed)
        dropped, attack_counts = dominant_attack_clients(y_train, indices, k=2)
        out_dir = Path(out_root) / f"edgeiiot_a{alpha}"
        out_dir.mkdir(parents=True, exist_ok=True)
        # filename kept for interface compatibility with the frozen loaders
        np.savez_compressed(out_dir / "unsw_subset.npz",
                            X_train=X_train, y_train=y_train, X_test=X_test, y_test=y_test)
        (out_dir / "client_indices.json").write_text(json.dumps(indices, indent=2), encoding="utf-8")
        manifest = {
            "preprocessing_version": "PBA3/E1-EdgeIIoT-train-only-v1",
            "source": "Edge-IIoTset (Ferrag et al.), DNN-EdgeIIoT-dataset.csv",
            "source_page": "https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot",
            "source_kaggle": "https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot",
            "source_sha256": sha256(CSV),
            "rows": {"full": int(len(df)), "used_train": int(len(tr)), "used_test": int(len(te))},
            "label_distribution": {
                "train": {"0": int((y_train == 0).sum()), "1": int((y_train == 1).sum())},
                "test": {"0": int((y_test == 0).sum()), "1": int((y_test == 1).sum())}},
            "features": len(numeric), "feature_names": numeric,
            "model_hidden": 32, "model_params": len(numeric) * 32 + 2 * 32 + 1,
            "clients": clients, "dirichlet_alpha": alpha, "partition_seed": seed,
            "partition_disjoint": True, "partition_exhaustive": True,
            "dropped_clients": dropped,
            "attack_rows_per_client": attack_counts,
            "note": "npz filename kept as unsw_subset.npz only for loader compatibility; corpus is Edge-IIoTset.",
        }
        (out_dir / "dataset_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        manifests[str(alpha)] = {"dir": str(out_dir), "features": len(numeric),
                                 "params": manifest["model_params"], "dropped_clients": dropped,
                                 "train_attack": int((y_train == 1).sum())}
        print(json.dumps({"alpha": alpha, "features": len(numeric), "params": manifest["model_params"],
                          "dropped_clients": dropped, "top_attack_counts": sorted(attack_counts, reverse=True)[:4]}, ensure_ascii=False))
    return manifests


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, default=Path(r".\data\edgeiiot_subset"))
    p.add_argument("--alphas", nargs="*", type=float, default=[0.1, 0.5, 1.0])
    a = p.parse_args()
    print(json.dumps(prepare(a.out, alphas=tuple(a.alphas)), ensure_ascii=False, indent=2))