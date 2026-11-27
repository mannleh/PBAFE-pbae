"""Independent matched CPU MLP runs; no synthetic or shared-update fallback."""
import argparse
import hashlib
import json
import os
import platform
import socket
import time
from pathlib import Path
import numpy as np
from sklearn.metrics import balanced_accuracy_score, f1_score, precision_score, recall_score
from .codec import SCALE, MAX_COORD, digest, encode_vector
from .repository import make_fixture, Keys
from .verify import audit

METHODS=("fedavg_no_audit","audit_enabled","periodic_full","policy_bound","policy_blind")


def sigmoid(z):
    return 1/(1+np.exp(-np.clip(z,-30,30)))


def unpack(w,d,h):
    a=d*h
    return w[:a].reshape(d,h),w[a:a+h],w[a+h:a+2*h],w[-1]


def predict(w,X,h):
    W,b,v,c=unpack(w,X.shape[1],h)
    return sigmoid(np.maximum(X@W+b,0)@v+c)


def local_update(w,X,y,h,rng,batch=128,lr=.03,class_weights=None):
    idx=rng.choice(len(y),min(batch,len(y)),replace=False)
    X,y=X[idx],y[idx]
    W,b,v,c=unpack(w,X.shape[1],h)
    z=X@W+b; hidden=np.maximum(z,0)
    e=(sigmoid(hidden@v+c)-y)
    if class_weights is not None:
        e=e*np.asarray([class_weights[int(label)] for label in y])
    e=e/len(y)
    dh=(e[:,None]*v[None,:])*(z>0)
    grad=np.concatenate([(X.T@dh).ravel(),dh.sum(axis=0),hidden.T@e,[e.sum()]])
    update=np.rint(-lr*grad*SCALE).astype(np.int64)
    if np.max(np.abs(update))>MAX_COORD:
        raise ValueError("fixed-point update bound")
    return update


def server_aggregate(vectors,counts):
    """Independent NumPy implementation; verifier uses Python bigint replay."""
    vectors=np.asarray(vectors,dtype=np.int64); counts=np.asarray(counts,dtype=np.int64)
    denominator=int(counts.sum())
    if int(np.max(np.abs(vectors)))*denominator > np.iinfo(np.int64).max:
        raise OverflowError("server numerator exceeds int64")
    numerator=(vectors*counts[:,None]).sum(axis=0,dtype=np.int64)
    q,r=np.divmod(np.abs(numerator),denominator)
    q=q+((2*r>denominator)|((2*r==denominator)&((q%2)==1)))
    return np.where(numerator<0,-q,q).astype(np.int64)


def metrics(w,X,y,h):
    pred=(predict(w,X,h)>=.5).astype(int)
    return {"f1":float(f1_score(y,pred,zero_division=0)),
            "precision":float(precision_score(y,pred,zero_division=0)),
            "recall":float(recall_score(y,pred,zero_division=0)),
            "balanced_accuracy":float(balanced_accuracy_score(y,pred))}


def run(data_dir,out,rounds=60,clients=30,selected=10,seeds=(101,102,103),hidden=32,learning_rate=.03):
    manifest=json.loads((data_dir/"dataset_manifest.json").read_text(encoding="utf8"))
    if manifest.get("preprocessing_version")!="PBA2/UNSW-train-only-v2":
        raise ValueError("final training requires corrected official-source preprocessing")
    if manifest.get("source_sha256") != {
        "train":"bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
        "test":"734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559"}:
        raise ValueError("official source checksums differ; re-verify provenance")
    data=np.load(data_dir/"unsw_subset.npz",allow_pickle=False)
    Xtr,ytr,Xte,yte=[data[k].astype(np.float64) for k in ("X_train","y_train","X_test","y_test")]
    indices=json.loads((data_dir/"client_indices.json").read_text(encoding="utf8"))
    flat=[i for block in indices for i in block]
    if len(indices)!=clients or any(not x for x in indices) or sorted(flat)!=list(range(len(ytr))):
        raise ValueError("partition must be nonempty, disjoint and exhaustive")
    rows=[]; round_rows=[]; d=Xtr.shape[1]; parameters=d*hidden+2*hidden+1
    keys=Keys.generate(range(clients))
    class_weights={0:len(y_train:=ytr)/(2*max(1,int((ytr==0).sum()))),1:len(ytr)/(2*max(1,int((ytr==1).sum())))}
    for seed in seeds:
        rng=np.random.default_rng(seed)
        initial=np.concatenate([rng.normal(0,.05,d*hidden),np.zeros(hidden),
                                rng.normal(0,.05,hidden),np.zeros(1)])
        schedule=[sorted(map(int,rng.choice(clients,selected,replace=False))) for _ in range(rounds)]
        reference=[]
        # Each method reruns training from its OWN model and RNG; no tensor sharing.
        for method in METHODS:
            w=initial.copy(); train_s=prepare_s=audit_s=0.; total_bytes=0; max_diff=0.
            for ri,chosen in enumerate(schedule):
                prev_model=w.copy(); t=time.perf_counter(); updates=[]; counts=[]
                for cid in chosen:
                    idx=np.asarray(indices[cid],dtype=int)
                    local_rng=np.random.default_rng(np.random.SeedSequence([seed,ri,cid,71]))
                    updates.append(local_update(w,Xtr[idx],ytr[idx],hidden,local_rng,lr=learning_rate,class_weights=class_weights))
                    counts.append(len(idx))
                aggregate=server_aggregate(updates,counts)
                actual_result=encode_vector(aggregate.tolist())
                w=w+aggregate/SCALE
                train_s+=time.perf_counter()-t
                if method=="fedavg_no_audit": reference.append(w.copy())
                else: max_diff=max(max_diff,float(np.max(np.abs(reference[ri]-w))))
                checked=None; prep=0.; duration=0.
                if method!="fedavg_no_audit":
                    start=time.perf_counter()
                    all_clients=list(range(clients))
                    selected_set=set(chosen)
                    counts_all=[0]*clients
                    updates_all=[[0]*parameters for _ in range(clients)]
                    for cid, update, count in zip(chosen, updates, counts):
                        counts_all[cid]=int(count)
                        updates_all[cid]=update.tolist()
                    f=make_fixture(round_id=ri+1,dimension=parameters,roster_ids=all_clients,
                        clients=clients,counts=counts_all,updates=updates_all,
                        absent_slots=set(all_clients)-selected_set,keys=keys,
                        model_hash=digest("PBA2/model",prev_model.astype(">f8").tobytes()),
                        actual_result=actual_result)
                    prep=time.perf_counter()-start; prepare_s+=prep
                    full=(ri+1)%10==0 and method in ("audit_enabled","periodic_full")
                    if full or method!="periodic_full":
                        audit_rng=np.random.default_rng(np.random.SeedSequence([seed,ri,991]))
                        slots=sorted(map(int,audit_rng.choice(clients,3,replace=False)))
                        checked=audit(f.source,f.trust,slots=slots,full=full,bound=method!="policy_blind")
                        duration=checked.wall_ms/1000; audit_s+=duration
                        total_bytes+=checked.total_network_bytes
                        if checked.outcome!="PASS": raise RuntimeError(str(checked.findings))
                round_rows.append({"seed":seed,"method":method,"round":ri+1,"chosen":chosen,
                    "parameter_difference":0. if method=="fedavg_no_audit" else float(np.max(np.abs(reference[ri]-w))),
                    "evidence_prepare_seconds":prep,"audit_seconds":duration,
                    "audit":None if checked is None else checked.as_dict()})
            row={"seed":seed,"method":method,"rounds":rounds,"parameters":parameters,
                 "train_seconds":train_s,"evidence_prepare_seconds":prepare_s,"audit_seconds":audit_s,
                 "total_audit_bytes":total_bytes,"max_parameter_difference":max_diff,**metrics(w,Xte,yte,hidden)}
            rows.append(row)
            print(json.dumps(row),flush=True)
    result={"status":"measured-candidate; pending research acceptance","protocol":"PBA/2",
        "configuration":{"rounds":rounds,"clients":clients,"selected_per_round":selected,
            "seeds":list(seeds),"model":"one-hidden-layer ReLU MLP","hidden":hidden,
            "batch_size":128,"local_steps":1,"learning_rate":learning_rate,"class_weights":class_weights,"parameters":parameters,
            "baseline":"deterministic fixed-point FedAvg, no audit","shared_client_updates":False},
        "environment":{"hostname":socket.gethostname(),"platform":platform.platform(),
            "python":platform.python_version(),"numpy":np.__version__,"threads":os.environ.get("OPENBLAS_NUM_THREADS")},
        "source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "dataset_manifest_sha256":hashlib.sha256((data_dir/"dataset_manifest.json").read_bytes()).hexdigest(),
        "runs":rows,"rounds":round_rows}
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2),encoding="utf8")
    return result


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--data-dir",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    p.add_argument("--rounds",type=int,default=60);p.add_argument("--seeds",type=int,nargs="+",default=[101,102,103])
    p.add_argument("--hidden",type=int,default=32);p.add_argument("--learning-rate",type=float,default=.03)
    a=p.parse_args();run(a.data_dir,a.out,a.rounds,seeds=a.seeds,hidden=a.hidden,learning_rate=a.learning_rate)
