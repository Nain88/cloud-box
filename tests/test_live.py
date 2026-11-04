import base64
import json
from pathlib import Path
import httpx
import pytest
from sqlalchemy import select,update
from test_core import service,wire
from test_api import app_client
from cbb.agent import Agent,SpoolFull
from cbb.firewall import tail_firewall,parse_record
from cbb.crypto import dumps,loads,uid,now,sha
from cbb.service import row,rows
from cbb import db as D

FIELDS='date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid'.split()
def record(port=443,action='DROP'):
    return f'2026-10-30 16:10:00 {action} TCP 192.0.2.10 192.0.2.20 50000 {port} 0 - 0 0 0 - - - RECEIVE 123\n'.encode()

def test_firewall_raw_bytes_header_cursor_partial_and_restart(tmp_path):
    source=tmp_path/'pfirewall.log';source.write_bytes(('#Time Format: Local\n#Fields: '+' '.join(FIELDS)+'\n').encode()+record()+b'partial')
    agent=Agent({'server':'http://127.0.0.1:8765','token':'test'},root=tmp_path/'spool',client=httpx.Client())
    tail_firewall(agent,source)
    batch=agent.spool.batch();assert len(batch)==1
    event=json.loads(batch[0]['body']);assert base64.b64decode(event['raw_base64'])==record()
    assert event['source_cursor']['fields']==FIELDS and event['original_timestamp']=='2026-10-30T16:10:00'
    tail_firewall(agent,source);assert len(agent.spool.batch())==1
    agent.close()
    agent=Agent({'server':'http://127.0.0.1:8765','token':'test'},root=tmp_path/'spool',client=httpx.Client())
    tail_firewall(agent,source);assert len(agent.spool.batch())==1
    agent.close()

def test_firewall_backpressure_preserves_record_cursor(tmp_path):
    source=tmp_path/'firewall.log';source.write_bytes(('#Fields: '+' '.join(FIELDS)+'\n').encode()+record())
    agent=Agent({'server':'http://127.0.0.1:8765','token':'test','spool_bytes':1},root=tmp_path/'spool',client=httpx.Client())
    with pytest.raises(SpoolFull):tail_firewall(agent,source)
    assert agent.spool.get('windows.firewall:'+str(source.resolve()))['offset']<source.stat().st_size
    agent.spool.max_bytes=1024*1024;tail_firewall(agent,source)
    assert len(agent.spool.batch())==1
    agent.close()

def test_firewall_burst_real_pipeline_and_no_attack_claim_for_single_drop(service):
    events=[wire(str(i),raw=record(1000+i),source_type='windows.firewall',event_type='firewall.drop',raw_media_type='text/plain',original_timestamp='2026-10-30T16:10:00',source_cursor={'fields':FIELDS}) for i in range(1,7)]
    accepted=service.accept(service.test_collector,events[:1]);service.seal_pending()
    service.analyze(accepted[0]['evidence_id'])
    with service.db.read() as c:assert not rows(c,select(D.alerts))
    accepted+=service.accept(service.test_collector,events[1:]);service.seal_pending()
    with service.db.read() as c:assert len(rows(c,select(D.alerts)))==1
    for item in accepted:service.analyze(item['evidence_id'])
    with service.db.read() as c:
        alerts=rows(c,select(D.alerts));assert len(alerts)==1
        assert alerts[0]['rule_id']=='FW-PORT-BURST/1.0'
        assert 'Possible scan' in alerts[0]['explanation'] and 'replay' in alerts[0]['explanation']
        item=row(c,select(D.evidence));assert service.read_raw(c,item)==record(1001)
        assert item['occurred_at'] is None and 'UNKNOWN_EVENT_TIME' in loads(item['envelope'])['quality_flags']

def test_live_scope_and_opt_in_intake(app_client):
    app,client=app_client;s=app.state.service
    token=client.post('/api/v1/enrollments',json={'name':'sensor','os':'Windows'}).json()['token']
    cred=s.enroll(token)
    with s.db.read() as c:col=row(c,select(D.collectors).where(D.collectors.c.id==cred['collector_id']))
    # Administrator sees no unassigned evidence.
    accepted=s.accept(col,[wire()]);s.seal_pending()
    assert client.get('/api/v1/live/events').json()['items']==[]
    cid=client.get('/api/v1/cases').json()[0]['id']
    assert client.put('/api/v1/collectors/'+col['id']+'/configuration',json={'intake_case_id':cid}).status_code==200
    s.accept(col,[wire('2')]);s.seal_pending()
    data=client.get('/api/v1/live/events').json();assert len(data['items'])==1
    assert data['items'][0]['sequence']==2
    assert client.get('/api/v1/live/events?limit=99999').status_code==422
    assert client.get('/api/v1/live/events?source=windows.firewall').json()['items']==[]
    with s.db.read() as c:assert row(c,select(D.custody).where(D.custody.c.action=='CASE_INTAKE'))
    client.delete('/api/v1/auth/session')
    assert client.get('/api/v1/live/events').status_code==401

def test_firewall_bad_fields_and_ip():
    with pytest.raises(ValueError):parse_record(record(),[])
    with pytest.raises(ValueError):parse_record(record().replace(b'192.0.2.10',b'not-an-ip'),FIELDS)

def test_unknown_firewall_row_preserved_without_stalling(tmp_path):
    source=tmp_path/'firewall.log'
    damaged=b'incomplete vendor row\xff\n'
    source.write_bytes(('#Fields: '+' '.join(FIELDS)+'\n').encode()+damaged+record())
    agent=Agent({'server':'http://127.0.0.1:8765','token':'test'},root=tmp_path/'spool',client=httpx.Client())
    tail_firewall(agent,source)
    events=[json.loads(r['body']) for r in agent.spool.batch()]
    assert [e['event_type'] for e in events]==['firewall.unparsed','firewall.drop']
    assert base64.b64decode(events[0]['raw_base64'])==damaged
    agent.close()
