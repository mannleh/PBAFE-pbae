from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT=Path('experiments/pba_v2/results/release_v3/figures'); OUT.mkdir(parents=True,exist_ok=True)

def box(ax,x,y,w,h,text,fc='#EAF2F8',ec='#24527A'):
    p=FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.02,rounding_size=0.02',facecolor=fc,edgecolor=ec,linewidth=1.4)
    ax.add_patch(p); ax.text(x+w/2,y+h/2,text,ha='center',va='center',fontsize=10,wrap=True)

def arrow(ax,x1,y1,x2,y2,style='-|>',color='#444'):
    ax.add_patch(FancyArrowPatch((x1,y1),(x2,y2),arrowstyle=style,mutation_scale=16,linewidth=1.2,color=color))

def architecture():
    fig,ax=plt.subplots(figsize=(12,5)); ax.set_xlim(0,12); ax.set_ylim(0,5); ax.axis('off')
    box(ax,.3,3.2,1.8,1,'Clients\nlocal data + updates')
    box(ax,3.0,3.2,2.1,1,'Selection / policy service\nindependent bulletin')
    box(ax,6.0,3.2,1.8,1,'Aggregation server\npossibly malicious',fc='#FDEDEC',ec='#A93226')
    box(ax,8.8,3.2,2.1,1,'Evidence repository\nupdates + openings',fc='#FCF3CF',ec='#9A7D0A')
    box(ax,3.0,.7,2.1,1,'Authorized auditor\nspot or full replay',fc='#E8F8F5',ec='#117864')
    box(ax,6.0,.7,1.8,1,'Optional anchor\ndigests only',fc='#F4ECF7',ec='#6C3483')
    arrow(ax,2.1,3.7,3.0,3.7); arrow(ax,5.1,3.7,6.0,3.7); arrow(ax,7.8,3.7,8.8,3.7)
    arrow(ax,7.0,3.2,4.4,1.7); arrow(ax,9.4,3.2,4.8,1.7); arrow(ax,5.1,1.2,6.0,1.2)
    ax.text(2.45,3.95,'signed update',ha='center',fontsize=8); ax.text(5.55,3.95,'accepted result',ha='center',fontsize=8); ax.text(7.1,2.25,'evidence',ha='center',fontsize=8); ax.text(7.0,1.0,'hash tuple',ha='center',fontsize=8)
    ax.text(.4,4.65,'Trust anchors: registered client keys + selection bulletin pin',fontsize=11,fontweight='bold')
    fig.tight_layout(); fig.savefig(OUT/'system_architecture.png',dpi=220,bbox_inches='tight'); plt.close(fig)

def workflow():
    fig,ax=plt.subplots(figsize=(12,4.4)); ax.set_xlim(0,12); ax.set_ylim(0,4.4); ax.axis('off')
    box(ax,.3,2.5,2.0,1,'1. Publish\nbulletin + roster root')
    box(ax,2.9,2.5,2.0,1,'2. Collect\nreceipts + openings')
    box(ax,5.5,2.5,2.0,1,'3. Commit\nstate root + result')
    box(ax,8.1,2.5,1.6,1,'4a. Spot\nb records',fc='#E8F8F5',ec='#117864')
    box(ax,10.2,2.5,1.5,1,'4b. Full\nreplay',fc='#FDEDEC',ec='#A93226')
    for x in (2.3,4.9,7.5): arrow(ax,x,3.0,x+.6,3.0)
    ax.text(8.9,1.65,'O(b log K + bd)\nPASS means sampled evidence only',ha='center',fontsize=9,color='#117864')
    ax.text(10.95,1.55,'O(K log K + K_a d)\naggregate_verified=true',ha='center',fontsize=9,color='#A93226')
    arrow(ax,9.0,2.5,8.9,1.0); arrow(ax,10.95,2.5,10.95,1.0)
    box(ax,3.4,.25,5.1,.75,'Output: PASS / FAIL_ROSTER / FAIL_POLICY / FAIL_RESULT_REPLAY / INCONCLUSIVE_EVIDENCE',fc='#F7F9F9',ec='#566573')
    arrow(ax,8.9,1.0,7.9,.95); arrow(ax,10.95,1.0,7.9,.95)
    ax.text(.4,4.05,'The two audit levels have deliberately different evidence semantics',fontsize=12,fontweight='bold')
    fig.tight_layout(); fig.savefig(OUT/'hierarchical_audit_workflow.png',dpi=220,bbox_inches='tight'); plt.close(fig)

architecture(); workflow()
print('generated diagrams')
