"""Bounded, explainable event-time correlation; never automatic blocking."""
from datetime import datetime, timedelta
from sqlalchemy import select, and_
from . import db as D
from .crypto import loads, dumps, uid, now
from .service import rows, row


def firewall_burst(service, c, item, env):
    if item['source_type'] != 'windows.firewall' or item['event_type'] != 'firewall.drop':return
    src=env['subject'].get('src_ip')
    if not src:return
    if not item['occurred_at']:return
    occurred=datetime.fromisoformat(item['occurred_at'].replace('Z','+00:00'))
    received=datetime.fromisoformat(item['received_at'].replace('Z','+00:00'))
    if (occurred-received).total_seconds()>30:return
    delayed=(received-occurred).total_seconds()>120
    start=(occurred-timedelta(seconds=60)).isoformat(timespec='milliseconds').replace('+00:00','Z')
    recent=rows(c,select(D.evidence).where(and_(D.evidence.c.asset_id==item['asset_id'],D.evidence.c.source_type=='windows.firewall',D.evidence.c.event_type=='firewall.drop',D.evidence.c.occurred_at>=start,D.evidence.c.occurred_at<=item['occurred_at'],D.evidence.c.sequence<=item['sequence'])).order_by(D.evidence.c.sequence.desc()).limit(1000))
    matches=[r for r in recent if loads(r['envelope'])['subject'].get('src_ip')==src]
    matches=[r for r in matches if ('DELAYED_EVENT' in loads(r['envelope'])['quality_flags'])==delayed and 'SOURCE_CLOCK_AHEAD' not in loads(r['envelope'])['quality_flags']]
    ports={loads(r['envelope'])['subject'].get('dst_port') for r in matches}-{'-',None}
    if len(ports)<5:return
    key=f"firewall-burst:{item['asset_id']}:{src}:{int(occurred.timestamp())//60}:{delayed}"
    if row(c,select(D.alerts.c.id).where(D.alerts.c.dedup_key==key)):return
    service.audit(c,'detector','FIREWALL_BURST_DETECTED',item['id'],details={'source_ip':src,'evidence_ids':[r['id'] for r in matches],'distinct_ports':len(ports)})
    c.execute(D.alerts.insert().values(id=uid(),evidence_id=item['id'],asset_id=item['asset_id'],rule_id='FW-PORT-BURST/2.0',severity=3,risk=60,explanation=f'{len(ports)} destination ports blocked for source {src} within a 60-second event-time window. {"Delayed delivery / replay." if delayed else "Recent activity."} Possible scan or benign blocked activity. Review the linked observations.',status='NEW',components=dumps({'distinct_ports':len(ports),'window_seconds':60,'time_basis':'occurred_at','delayed':delayed,'evidence_ids':[r['id'] for r in matches],'candidate_limit':1000}),created_at=now(),dedup_key=key))
