#!/usr/bin/env python3
"""Measured two-host TCP transfer, not a wireless-deployment claim."""
import argparse,json,socket,struct,time
from pathlib import Path
from .repository import build_round
from .verify import audit

def payloads(dimension,k=30,b=3):
    source,trust=build_round(clients=k,dimension=dimension,selected=list(range(10)),seed=260915)
    T=type("Trust",(),trust)(); spot=audit(source,T,slots=list(range(b))); full=audit(source,T,full=True)
    # The payload is the exact concatenation of objects read by each interface.
    def raw(names): return b''.join(source[n] for n in names if n in source)
    spot_names=["bulletin","policy","snapshot"]
    for slot in range(b):
        spot_names += [f"record/{slot}/{x}" for x in ("roster","roster_proof","state","state_proof","receipt","opening","update")]
    full_names=["bulletin","policy","snapshot"]
    for slot in range(k):
        full_names += [f"record/{slot}/{x}" for x in ("roster","roster_proof","state","state_proof")]
        if f"record/{slot}/receipt" in source: full_names += [f"record/{slot}/{x}" for x in ("receipt","opening","update")]
        else: full_names += [f"record/{slot}/disposition"]
    full_names += ["result"]
    return {"spot":raw(spot_names),"full":raw(full_names),"audit_spot":spot.as_dict(),"audit_full":full.as_dict()}

def serve(host,port,out,expected=30):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((host,port)); s.listen(8); rows=[]
    while len(rows)<expected:
        c,a=s.accept(); start=time.perf_counter(); head=c.recv(8)
        if len(head)!=8: c.close(); continue
        n=struct.unpack('!Q',head)[0]; got=0
        while got<n:
            chunk=c.recv(min(1024*1024,n-got))
            if not chunk: break
            got+=len(chunk)
        c.sendall(struct.pack('!Q',got)); c.close(); rows.append({'peer':a[0],'bytes':got,'wall_ms':(time.perf_counter()-start)*1000})
    Path(out).write_text(json.dumps(rows,indent=2),encoding='utf8')

def client(host,port,out,dimensions=(43,256,972),reps=5):
    rows=[]
    for d in dimensions:
        p=payloads(d)
        for kind in ('spot','full'):
            for rep in range(reps):
                start=time.perf_counter(); s=socket.create_connection((host,port),timeout=120); data=p[kind]; s.sendall(struct.pack('!Q',len(data))+data); ack=s.recv(8); s.close(); elapsed=(time.perf_counter()-start)*1000
                rows.append({'dimension':d,'kind':kind,'rep':rep,'payload_bytes':len(data),'ack_bytes':struct.unpack('!Q',ack)[0],'wall_ms':elapsed,'local_audit_bytes':p['audit_'+kind]['total_network_bytes']})
    Path(out).write_text(json.dumps(rows,indent=2),encoding='utf8')

if __name__=='__main__':
 p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='mode',required=True); q=sub.add_parser('serve'); q.add_argument('--host',default='0.0.0.0'); q.add_argument('--port',type=int,required=True); q.add_argument('--out',type=Path,required=True); q.add_argument('--expected',type=int,default=30); q=sub.add_parser('client'); q.add_argument('--host',required=True); q.add_argument('--port',type=int,required=True); q.add_argument('--out',type=Path,required=True); a=p.parse_args(); (serve(a.host,a.port,a.out,a.expected) if a.mode=='serve' else client(a.host,a.port,a.out))

