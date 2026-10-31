"""Bounded, explainable receipt-window correlation; never automatic blocking."""
from datetime import datetime, timedelta
from sqlalchemy import select, and_
from . import db as D
from .crypto import loads, dumps, uid, now
from .service import rows, row


def firewall_burst(service, c, item, env):
    if item['source_type'] != 'windows.firewall' or item['event_type'] != 'firewall.drop':return
    src=env['subject'].get('src_ip')
    if not src:return
    received=datetime.fromisoformat(item['received_at'].replace('Z','+00:00'))
    start=(received-timedelta(seconds=60)).isoformat(timespec='milliseconds').replace('+00:00','Z')
    recent=rows(c,select(D.evidence).where(and_(D.evidence.c.asset_id==item['asset_id'],D.evidence.c.source_type=='windows.firewall',D.evidence.c.event_type=='firewall.drop',D.evidence.c.received_at>=start,D.evidence.c.sequence<=item['sequence'])).order_by(D.evidence.c.sequence.desc()).limit(1000))
    matches=[r for r in recent if loads(r['envelope'])['subject'].get('src_ip')==src]
    ports={loads(r['envelope'])['subject'].get('dst_port') for r in matches}-{'-',None}
    if len(ports)<5:return
    key=f"firewall-burst:{item['asset_id']}:{src}:{int(received.timestamp())//60}"
    if row(c,select(D.alerts.c.id).where(D.alerts.c.dedup_key==key)):return
    service.audit(c,'detector','FIREWALL_BURST_DETECTED',item['id'],details={'source_ip':src,'evidence_ids':[r['id'] for r in matches],'distinct_ports':len(ports)})
    c.execute(D.alerts.insert().values(id=uid(),evidence_id=item['id'],asset_id=item['asset_id'],rule_id='FW-PORT-BURST/1.0',severity=3,risk=60,explanation=f'{len(ports)} destination ports blocked for source {src} within a 60-second receipt window. Possible scan or benign blocked activity; delayed replay can also trigger this rule. Review the linked observations.',status='NEW',components=dumps({'distinct_ports':len(ports),'window_seconds':60,'time_basis':'received_at','evidence_ids':[r['id'] for r in matches],'candidate_limit':1000}),created_at=now(),dedup_key=key))
