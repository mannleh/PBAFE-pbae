#!/usr/bin/env python3
"""Official-source UNSW-NB15 preparation with train-only fitting and safe partitions."""
import argparse, hashlib, json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from pandas.api.types import is_numeric_dtype

DROP={"id","label","attack_cat"}

def sha256(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()

def encode_train_test(train,test):
    train=train.drop(columns=[c for c in DROP if c in train],errors="ignore")
    test=test.drop(columns=[c for c in DROP if c in test],errors="ignore")
    categorical=[c for c in train.columns if not is_numeric_dtype(train[c])]
    train=pd.get_dummies(train,columns=categorical,dummy_na=True)
    test=pd.get_dummies(test,columns=[c for c in categorical if c in test],dummy_na=True)
    test=test.reindex(columns=train.columns,fill_value=0)
    train=train.replace([np.inf,-np.inf],np.nan).fillna(0.0)
    test=test.replace([np.inf,-np.inf],np.nan).fillna(0.0)
    train=train.apply(pd.to_numeric,errors="coerce").fillna(0.0)
    test=test.apply(pd.to_numeric,errors="coerce").fillna(0.0)
    train_array=train.to_numpy(dtype=np.float64)
    test_array=test.to_numpy(dtype=np.float64)
    scaler=StandardScaler().fit(train_array)
    return scaler.transform(train_array).astype(np.float32),scaler.transform(test_array).astype(np.float32),list(train.columns),categorical

def partition(y,clients,alpha,seed):
    rng=np.random.default_rng(seed); out=[[] for _ in range(clients)]
    for label in sorted(set(map(int,y))):
        ids=np.flatnonzero(y==label); rng.shuffle(ids)
        props=rng.dirichlet(np.full(clients,alpha)); cuts=np.floor(np.cumsum(props)*len(ids)).astype(int)[:-1]
        for c,block in enumerate(np.split(ids,cuts)): out[c].extend(map(int,block))
    # Ensure every registered client can be selected without borrowing data.
    for c in range(clients):
        if not out[c]:
            donor=max(range(clients),key=lambda j:len(out[j]))
            if len(out[donor])<=1: raise ValueError("not enough training rows for nonempty clients")
            out[c].append(out[donor].pop())
    for block in out: rng.shuffle(block)
    flat=[i for block in out for i in block]
    if len(flat)!=len(set(flat)) or set(flat)!=set(range(len(y))): raise AssertionError("partition is not disjoint/exhaustive")
    return out

def prepare(train_path,test_path,out_dir,clients=30,alpha=.5,max_train=12000,max_test=4000,seed=7):
    train_full=pd.read_csv(train_path); test_full=pd.read_csv(test_path)
    rng=np.random.default_rng(seed)
    train=train_full.sample(min(max_train,len(train_full)),random_state=seed).reset_index(drop=True)
    test=test_full.sample(min(max_test,len(test_full)),random_state=seed+1).reset_index(drop=True)
    y_train=train["label"].astype(int).to_numpy(); y_test=test["label"].astype(int).to_numpy()
    x_train,x_test,feature_names,categorical_columns=encode_train_test(train,test)
    indices=partition(y_train,clients,alpha,seed)
    out_dir.mkdir(parents=True,exist_ok=True)
    np.savez_compressed(out_dir/"unsw_subset.npz",X_train=x_train,y_train=y_train,X_test=x_test,y_test=y_test)
    (out_dir/"client_indices.json").write_text(json.dumps(indices,indent=2),encoding="utf8")
    manifest={"preprocessing_version":"PBA2/UNSW-train-only-v2","source":"UNSW Research official SharePoint dataset folder","source_page":"https://research.unsw.edu.au/projects/unsw-nb15-dataset","source_train":str(Path(train_path).resolve()),"source_test":str(Path(test_path).resolve()),"source_sha256":{"train":sha256(train_path),"test":sha256(test_path)},"rows":{"official_train":len(train_full),"official_test":len(test_full),"used_train":len(train),"used_test":len(test)},"label_distribution":{"train":{"0":int((y_train==0).sum()),"1":int((y_train==1).sum())},"test":{"0":int((y_test==0).sum()),"1":int((y_test==1).sum())}},"features":len(feature_names),"feature_names":feature_names,"excluded_columns":sorted(DROP),"categorical_columns":categorical_columns,"categorical_fit_split":"training only","clients":clients,"dirichlet_alpha":alpha,"partition_seed":seed,"partition_disjoint":True,"partition_exhaustive":True}
    (out_dir/"dataset_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf8")
    return manifest

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--train",type=Path,required=True); p.add_argument("--test",type=Path,required=True); p.add_argument("--out",type=Path,required=True); p.add_argument("--max-train",type=int,default=12000); p.add_argument("--max-test",type=int,default=4000); a=p.parse_args(); print(json.dumps(prepare(a.train,a.test,a.out,max_train=a.max_train,max_test=a.max_test),indent=2))
