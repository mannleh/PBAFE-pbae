# -*- coding: utf-8 -*-
"""Large-sample Edge-IIoTset preparation for E1-L.

Reads the source CSV in chunks, removes exact feature/label duplicates, draws
independent stratified train/test samples, and builds multiple Dirichlet client
partitions with sample and partition seeds kept separate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, r".")
from experiments.pba_v2.prepare_unsw_official import partition
from experiments.e1_edge.prepare_edgeiiot import dominant_attack_clients

CSV = Path(r".\data\archive\Edge-IIoTset dataset\Selected dataset for ML and DL\DNN-EdgeIIoT-dataset.csv")
LABEL = "Attack_label"
ATTACK_TYPE = "Attack_type"
DEFAULT_FEATURE_MANIFEST = Path(r".\data\edgeiiot_subset\edgeiiot_a0.5\dataset_manifest.json")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def allocate(counts: np.ndarray, total: int) -> np.ndarray:
    counts = np.asarray(counts, dtype=np.int64)
    if total > int(counts.sum()):
        raise ValueError(f"requested {total} rows but only {int(counts.sum())} unique rows")
    quota = np.minimum(counts, np.floor(counts * total / counts.sum()).astype(np.int64))
    while int(quota.sum()) < total:
        need = total - int(quota.sum())
        room = counts - quota
        score = counts * total / counts.sum() - quota
        score[room <= 0] = -np.inf
        for i in np.argsort(-score)[:need]:
            quota[i] += 1
    while int(quota.sum()) > total:
        i = int(np.argmax(quota))
        quota[i] -= 1
    return quota


def load_unique(csv: Path, features: list[str], chunk_size: int):
    usecols = features + [LABEL, ATTACK_TYPE]
    xs, ys, codes, source_rows = [], [], [], []
    seen = set()
    attack_map: dict[str, int] = {}
    raw_rows = 0
    duplicate_rows = 0
    for chunk in pd.read_csv(csv, usecols=usecols, chunksize=chunk_size, low_memory=False):
        raw_rows += len(chunk)
        clean = chunk[features].replace([np.inf, -np.inf], np.nan).fillna(0.0)
        clean = clean.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        x = clean.to_numpy(dtype=np.float32)
        y = chunk[LABEL].astype(np.int8).to_numpy()
        hashed = pd.util.hash_pandas_object(chunk[features + [LABEL]], index=False).to_numpy(dtype=np.uint64)
        unique_hash, first = np.unique(hashed, return_index=True)
        keep = []
        for h, pos in zip(unique_hash, first):
            key = int(h)
            if key not in seen:
                seen.add(key)
                keep.append(int(pos))
        if not keep:
            duplicate_rows += len(chunk)
            continue
        keep = np.asarray(keep, dtype=np.int64)
        duplicate_rows += len(chunk) - len(keep)
        at = chunk[ATTACK_TYPE].astype(str).to_numpy()[keep]
        code = np.empty(len(at), dtype=np.int16)
        for i, name in enumerate(at):
            if name not in attack_map:
                attack_map[name] = len(attack_map)
            code[i] = attack_map[name]
        xs.append(x[keep])
        ys.append(y[keep])
        codes.append(code)
        source_rows.append(keep + raw_rows - len(chunk))
    x = np.concatenate(xs, axis=0)
    y = np.concatenate(ys, axis=0)
    code = np.concatenate(codes, axis=0)
    source = np.concatenate(source_rows, axis=0)
    attack_names = [name for name, _ in sorted(attack_map.items(), key=lambda kv: kv[1])]
    stats = {
        "raw_rows": raw_rows,
        "unique_rows": int(len(y)),
        "duplicate_rows_removed": duplicate_rows,
        "attack_names": attack_names,
        "attack_counts_unique": np.bincount(code, minlength=len(attack_names)).tolist(),
    }
    return x, y, code, source, stats


def draw_sample(x, y, code, source, attack_names, seed, n_train, n_test):
    rng = np.random.default_rng(seed)
    counts = np.bincount(code, minlength=len(attack_names))
    train_quota = allocate(counts, n_train)
    test_quota = allocate(counts, n_test)
    train_parts, test_parts = [], []
    for c in range(len(attack_names)):
        ids = np.flatnonzero(code == c)
        perm = rng.permutation(ids)
        nt = int(test_quota[c])
        nr = int(train_quota[c])
        if nt + nr > len(ids):
            raise ValueError(f"attack type {attack_names[c]} quota {nt + nr} exceeds {len(ids)} unique rows")
        test_parts.append(perm[:nt])
        train_parts.append(perm[nt:nt + nr])
    train_idx = np.concatenate(train_parts)
    test_idx = np.concatenate(test_parts)
    rng.shuffle(train_idx)
    rng.shuffle(test_idx)
    if set(train_idx.tolist()).intersection(test_idx.tolist()):
        raise AssertionError("train/test overlap")
    return train_idx, test_idx, train_quota.tolist(), test_quota.tolist()


def prepare(sample_seeds, partition_seeds, alphas, clients, n_train, n_test,
            hidden, out_root: Path, csv: Path, feature_manifest: Path, chunk_size: int):
    feature_obj = json.loads(feature_manifest.read_text(encoding="utf-8"))
    features = list(feature_obj["feature_names"])
    if "frame.time" in features:
        raise ValueError("frame.time must not be a model feature")
    out_root.mkdir(parents=True, exist_ok=False)
    source_sha = sha256_file(csv)
    x, y, code, source, dedup = load_unique(csv, features, chunk_size)
    attack_names = dedup["attack_names"]
    print(json.dumps({"stage": "unique_data", **{k: v for k, v in dedup.items() if k != 'attack_names'}}), flush=True)

    for sample_seed in sample_seeds:
        train_idx, test_idx, train_quota, test_quota = draw_sample(
            x, y, code, source, attack_names, sample_seed, n_train, n_test)
        x_train_raw = x[train_idx]
        x_test_raw = x[test_idx]
        y_train = y[train_idx]
        y_test = y[test_idx]
        scaler = StandardScaler().fit(x_train_raw)
        x_train = scaler.transform(x_train_raw).astype(np.float32)
        x_test = scaler.transform(x_test_raw).astype(np.float32)
        del x_train_raw, x_test_raw

        sample_dir = out_root / f"sample_s{sample_seed}"
        sample_dir.mkdir(parents=True, exist_ok=False)
        np.savez_compressed(sample_dir / "unsw_subset.npz",
                            X_train=x_train, y_train=y_train, X_test=x_test, y_test=y_test)
        np.save(sample_dir / "train_source_rows.npy", source[train_idx])
        np.save(sample_dir / "test_source_rows.npy", source[test_idx])
        sample_manifest = {
            "preprocessing_version": "PBA3/E1-L-v1",
            "source": "Edge-IIoTset (Ferrag et al.), DNN-EdgeIIoT-dataset.csv",
            "source_sha256": source_sha,
            "feature_manifest": str(feature_manifest.resolve()),
            "features": features,
            "feature_count": len(features),
            "excluded_fields": ["frame.time", "ip.src_host", "ip.dst_host", "Attack_type", "Attack_label"],
            "dedup": {k: v for k, v in dedup.items() if k != "attack_names"},
            "sample_seed": sample_seed,
            "rows": {"train": int(len(y_train)), "test": int(len(y_test))},
            "label_distribution": {
                "train": {"0": int((y_train == 0).sum()), "1": int((y_train == 1).sum())},
                "test": {"0": int((y_test == 0).sum()), "1": int((y_test == 1).sum())},
            },
            "attack_names": attack_names,
            "attack_quota_train": train_quota,
            "attack_quota_test": test_quota,
            "scaler": "StandardScaler fit on train only",
            "npz_sha256": sha256_file(sample_dir / "unsw_subset.npz"),
            "model_hidden": hidden,
            "model_params": hidden * (len(features) + 2) + 1,
        }
        write_json(sample_dir / "sample_manifest.json", sample_manifest)
        print(json.dumps({"stage": "sample", "sample_seed": sample_seed,
                          "train": len(y_train), "test": len(y_test),
                          "train_attack": int(y_train.sum()), "test_attack": int(y_test.sum())}), flush=True)

        for partition_seed in partition_seeds:
            for alpha in alphas:
                indices = partition(y_train, clients, alpha, partition_seed)
                dropped, attack_counts = dominant_attack_clients(y_train, indices, k=2)
                sizes = np.asarray([len(block) for block in indices], dtype=np.int64)
                cell_dir = sample_dir / f"a{alpha}_p{partition_seed}"
                cell_dir.mkdir(parents=True, exist_ok=False)
                (cell_dir / "client_indices.json").write_text(
                    json.dumps(indices, indent=2), encoding="utf-8")
                cell_manifest = {
                    "sample_seed": sample_seed,
                    "partition_seed": partition_seed,
                    "dirichlet_alpha": alpha,
                    "clients": clients,
                    "selected_per_round": clients // 3,
                    "audit_budget": 3,
                    "dropped_clients": dropped,
                    "attack_rows_per_client": attack_counts,
                    "client_size_stats": {
                        "min": int(sizes.min()), "p5": int(np.percentile(sizes, 5)),
                        "median": float(np.median(sizes)), "p95": int(np.percentile(sizes, 95)),
                        "max": int(sizes.max()),
                    },
                    "clients_below_128": int((sizes < 128).sum()),
                    "sample_manifest_sha256": sha256_file(sample_dir / "sample_manifest.json"),
                    "client_indices_sha256": sha256_file(cell_dir / "client_indices.json"),
                    "partition_disjoint": True,
                    "partition_exhaustive": True,
                }
                write_json(cell_dir / "dataset_manifest.json", cell_manifest)
                print(json.dumps({"stage": "cell", "sample_seed": sample_seed,
                                  "partition_seed": partition_seed, "alpha": alpha,
                                  "dropped": dropped, **cell_manifest["client_size_stats"]}), flush=True)
        del x_train, x_test, y_train, y_test
    return out_root


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", type=Path, default=CSV)
    p.add_argument("--feature-manifest", type=Path, default=DEFAULT_FEATURE_MANIFEST)
    p.add_argument("--out", type=Path, default=Path(r".\data\edgeiiot_large"))
    p.add_argument("--sample-seeds", nargs="+", type=int, default=[101, 102])
    p.add_argument("--partition-seeds", nargs="+", type=int, default=[7, 17])
    p.add_argument("--alphas", nargs="+", type=float, default=[0.1, 0.5, 1.0])
    p.add_argument("--clients", type=int, default=30)
    p.add_argument("--train", type=int, default=200000)
    p.add_argument("--test", type=int, default=50000)
    p.add_argument("--hidden", type=int, default=142)
    p.add_argument("--chunk-size", type=int, default=100000)
    a = p.parse_args()
    prepare(a.sample_seeds, a.partition_seeds, a.alphas, a.clients, a.train, a.test,
            a.hidden, a.out, a.csv, a.feature_manifest, a.chunk_size)


if __name__ == "__main__":
    main()
