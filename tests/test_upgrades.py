"""Real local algorithms/renderers; vendor transfer is simulated, not a live MEGA claim."""
import json
import zipfile
from pathlib import Path
import pytest
from sqlalchemy import select,update
from fastapi.testclient import TestClient
from test_core import service,ingest,wire
from test_api import app_client
from cbb import db as D
from cbb.crypto import uid,now,sha,canon,dumps,loads,verify_signature
from cbb.service import row,rows,DomainError
from cbb.cloud import replicate_mega,restore_check
from cbb.assistant import analyze_case
from cbb.verify import verify_package

def case_fixture(s):
    results=ingest(s,4);actor=uid();cid=uid();ids=[r['evidence_id'] for r in results]
    with s.db.tx() as c:
        c.execute(D.users.insert().values(id=actor,username='analysis-owner',password_hash='not-a-real-login',role='investigator',active=True,created_at=now()))
        c.execute(D.cases.insert().values(id=cid,title='Case <untrusted> & review',description='Preserved scope',owner_id=actor,status='OPEN',severity=3,version=1,hold=True,created_at=now(),updated_at=now()))
        for eid in ids:c.execute(D.case_evidence.insert().values(id=uid(),case_id=cid,evidence_id=eid,case_version=1,active=True,reason='Test selection',created_at=now()))
    return {'case_id':cid,'case_version':1,'actor_id':actor,'evidence_ids':ids,'engine':'local','question':'authentication failures'}

def test_real_local_ai_and_report_snapshot(service):
    payload=case_fixture(service);result=analyze_case(service,payload)
    with service.db.read() as c:
        analysis=row(c,select(D.ai_runs));case=row(c,select(D.cases))
        document=loads(analysis['document'])
        assert document['engine']=='local-tfidf-clustering/1.0'
        assert document['review_state']=='UNREVIEWED' and document['similarity_groups']
        assert all(set(f['evidence_ids'])<=set(payload['evidence_ids']) for f in document['advice']['findings'])
        assert sha(canon(document))==analysis['output_sha256']
    report=service.make_export(payload['case_id'],payload['actor_id'],payload['evidence_ids'],1,case,[],[analysis])
    path=service.root/'exports'/(report['export_id']+'.zip')
    assert verify_package(path,service.deployment['public_key'])['status']=='VALID'
    with zipfile.ZipFile(path) as z:
        assert z.read('report.pdf').startswith(b'%PDF')
        import io
        from docx import Document
        document=Document(io.BytesIO(z.read('report.docx')))
        text='\n'.join(p.text for p in document.paragraphs)
        assert 'UNREVIEWED' in text and 'Case <untrusted> & review' in text
        assert json.loads(z.read('ai-assistance.json'))[0]['id']==result['analysis_id']
        assert json.loads(z.read('custody.json'))

def test_ai_rejects_revoked_scope(service):
    payload=case_fixture(service)
    with service.db.tx() as c:c.execute(update(D.case_evidence).values(active=False))
    with pytest.raises(DomainError,match='SCOPE_CHANGED'):analyze_case(service,payload)

def test_ai_rejects_fabricated_llm_citation(service,monkeypatch):
    payload=case_fixture(service);payload['engine']='ollama';monkeypatch.setenv('CBB_OLLAMA_MODEL','local-model')
    class Response:
        content=b'{}'
        def raise_for_status(self):pass
        def json(self):return {'message':{'content':json.dumps({'summary':'untrusted','findings':[{'text':'claim','evidence_ids':['fabricated-id']}],'next_steps':[],'limitations':[]})}}
    class Client:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def post(self,*args,**kwargs):return Response()
    monkeypatch.setattr('cbb.assistant.httpx.Client',Client)
    with pytest.raises(DomainError,match='AI_CITATION'):analyze_case(service,payload)
    with service.db.read() as c:assert not rows(c,select(D.ai_runs))

def mega_fake(monkeypatch,remote,corrupt=False):
    def command(verb,*args,**kwargs):
        if verb=='put':remote[args[1].rstrip('/')+'/'+Path(args[0]).name]=Path(args[0]).read_bytes()
        if verb=='get':(Path(args[1])/Path(args[0]).name).write_bytes(b'bad' if corrupt else remote[args[0]])
        return 'test-only'
    monkeypatch.setattr('cbb.cloud.mega_command',command)

def enable_mega(s):
    with s.db.tx() as c:c.execute(D.config.insert().values(id='mega-policy',value=dumps({'enabled':True}),version=1,updated_at=now()))

def test_mega_includes_evidence_proofs_artifacts_reports_and_verified_restore(service,monkeypatch):
    payload=case_fixture(service);enable_mega(service);remote={};mega_fake(monkeypatch,remote)
    art=service.root/'artifacts'/'original.bin';art.write_bytes(b'original acquired bytes')
    acquired=service.accept(service.test_collector,[wire('5',raw=canon({'sha256':sha(art.read_bytes()),'summary':'Acquisition test bytes'}),source_type='acquisition')])[0]
    service.seal_pending();payload['evidence_ids'].append(acquired['evidence_id'])
    with service.db.tx() as c:c.execute(D.artifacts.insert().values(id=uid(),path='artifacts/original.bin',name='original.bin',size=art.stat().st_size,sha256=sha(art.read_bytes()),evidence_id=acquired['evidence_id'],case_id=payload['case_id'],created_at=now()))
    service.make_export(payload['case_id'],payload['actor_id'],payload['evidence_ids'],1)
    result=replicate_mega(service,payload)
    assert result['uploaded_and_verified']>=6
    signed=json.loads(remote[result['inventory_remote_path']]);inventory=verify_signature(signed,'CBB-EXPORT-v1',service.deployment['public_key'])
    kinds={r['source_kind'] for r in inventory['objects']}
    assert {'segment','manifest','artifact','report-package','checkpoint','metadata-snapshot'}<=kinds
    assert all('/keys/' not in path and 'sqlite' not in path for path in remote)
    item=next(r for r in inventory['objects'] if r['source_kind']=='artifact')
    restored=restore_check(service,{'object_id':item['id'],'actor_id':payload['actor_id']})
    assert (service.root/restored['staging_path']).read_bytes()==art.read_bytes()
    assert restored['originals_replaced'] is False
    remote[item['remote_path']]=b'changed remotely'
    with pytest.raises(DomainError,match='REMOTE_HASH_MISMATCH'):restore_check(service,{'object_id':item['id'],'actor_id':payload['actor_id']})
    with service.db.read() as c:assert row(c,select(D.cloud_objects).where(D.cloud_objects.c.id==item['id']))['state']=='MISMATCH'

def test_mega_readback_mismatch_never_records_verified(service,monkeypatch):
    ingest(service);enable_mega(service);mega_fake(monkeypatch,{},corrupt=True)
    with pytest.raises(DomainError,match='REMOTE_HASH_MISMATCH'):replicate_mega(service,{'actor_id':'test'})
    with service.db.read() as c:assert not rows(c,select(D.cloud_objects))

def test_upgrade_routes_validation_and_scope(app_client):
    app,client=app_client;cid=client.get('/api/v1/cases').json()[0]['id']
    assert client.put('/api/v1/cloud/mega/settings',json={'enabled':'false'}).status_code==422
    assert client.put('/api/v1/cloud/mega/settings',json={'enabled':True,'remote_root':'/../keys'}).status_code==422
    assert client.post('/api/v1/cloud/mega/backup').status_code==422
    assert client.post('/api/v1/ai/analyses',json={'case_id':cid,'question':'inspect observations'}).status_code==422
    assert client.get('/api/v1/ai/analyses?case_id=missing').status_code==404
    assert client.put('/api/v1/cloud/mega/settings',json={'enabled':True,'automatic':False}).status_code==200
    a=client.post('/api/v1/cloud/mega/backup').json();b=client.post('/api/v1/cloud/mega/backup').json();assert a==b
    client.post('/api/v1/users',json={'username':'restricted-user','password':'test-password-long-enough','role':'reviewer'})
    with TestClient(app) as other:
        auth=other.post('/api/v1/auth/session',json={'username':'restricted-user','password':'test-password-long-enough'}).json();other.headers['x-csrf-token']=auth['csrf']
        assert other.get('/api/v1/integrations').status_code==403
        assert other.get('/api/v1/cloud/objects').status_code==403
        assert other.get('/api/v1/ai/analyses?case_id='+cid).status_code==404

def test_sensor_health_freshness_and_missing_input(tmp_path):
    from cbb.sensor_health import input_health
    eve=tmp_path/'eve.json';eve.write_text('{}\n')
    (tmp_path/'sensor-status.json').write_text(json.dumps({'state':'RUNNING','updated_at':'2020-01-01T00:00:00+00:00'}))
    health=input_health([str(eve),str(tmp_path/'missing.json')])
    assert health[0]['sensor']['fresh'] is False
    assert health[1]['state']=='MISSING'

def test_vendor_probe_does_not_wait_for_inherited_service_pipe(tmp_path):
    import sys,time
    from cbb.tooling import bounded_process
    # Model a client that starts a background service inheriting its output.
    code="import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)']); print('client-ready',flush=True)"
    started=time.monotonic();status,output=bounded_process([sys.executable,'-c',code],3)
    assert status==0 and 'client-ready' in output
    assert time.monotonic()-started<4

def test_vendor_probe_timeout_is_bounded():
    import sys,subprocess
    from cbb.tooling import bounded_process
    with pytest.raises(subprocess.TimeoutExpired):bounded_process([sys.executable,'-c','import time; time.sleep(10)'],.1)
