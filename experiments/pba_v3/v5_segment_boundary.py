"""Reproduce the existing segment/client-binding gap; NOT a proposed redesign."""
import argparse
from dataclasses import replace
from pathlib import Path
from .codec import Tree, canon, decode_vector, digest, encode_vector, leaf, sign
from .repository import put
from .segfixture import build_segment_fixture
from .verify import audit, audit_segment, PASS, FAIL_RESULT_REPLAY
from .v5_common import write_json


def check():
    f=build_segment_fixture(dimension=16,clients=4,segments=2,seed=90211)
    receipt_bytes={c:f.source[f"record/{c}/receipt"] for c in range(4)}
    original=f.obj("record/0/contribution/0")
    altered=list(original)
    altered[0]+=123456
    put(f.source,"record/0/contribution/0",altered)
    leaves=[]
    for s in range(2):
        values=[f.obj(f"record/{c}/contribution/{s}") for c in range(4)]
        for c,v in enumerate(values):
            leaves.append(leaf({"segment":s,"record":c,"contribution":v}))
        put(f.source,f"segment/{s}",[sum(v[j] for v in values) for j in range(len(values[0]))])
    tree=Tree(leaves)
    for s in range(2):
        for c in range(4):
            put(f.source,f"segment/{s}/proof/{c}",tree.proof(s*4+c))
    # A malicious server's changed result is pinned before challenges, just as
    # its internally consistent but unauthenticated contributions are pinned.
    result=decode_vector(f.source["result"],16)
    result[0]+=1
    f.source["result"]=encode_vector(result)
    body=f.obj("snapshot")["body"]
    body["segment_root"]=tree.root
    body["result_digest"]=digest("PBA2/result",f.source["result"])
    env=sign(f.keys.server,"PBA2/server",body)
    put(f.source,"snapshot",env)
    f.trust=replace(f.trust,snapshot_pin=digest("PBA2/snapshot",canon(env)))
    assert all(f.source[f"record/{c}/receipt"]==raw for c,raw in receipt_bytes.items())
    segment=audit_segment(f.source,f.trust,"12"*32,2)
    records=audit(f.source,f.trust,slots=list(range(4)))
    full=audit(f.source,f.trust,full=True)
    assert segment.outcome==PASS and records.outcome==PASS
    assert full.outcome==FAIL_RESULT_REPLAY
    return {"status":"REPRODUCED", "clients":4,"segments_checked":2,"segments_total":2,
            "client_receipts_unchanged":True,"old_contribution":original[0],
            "altered_contribution":altered[0],"segment_outcome":segment.outcome,
            "all_record_outcome":records.outcome,"full_result_replay_outcome":full.outcome,
            "segment_requests":segment.requests,"full_findings":full.findings,
            "scope":"existing implementation boundary, not a new attack against a client-authenticated segment design"}


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    if a.out.exists(): raise FileExistsError(a.out)
    write_json(a.out,check())
    print("Existing segment/client-binding counterexample reproduced")
