"""Offline, local-owner setup of a dedicated collector and visible intake case.
Requires the application's data directory to be stopped and exclusively locked.
No account passwords are modified or printed.
"""
import json,os,secrets,sys,time
from pathlib import Path
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root))
from sqlalchemy import select,update
from cbb.cli import exclusive
from cbb.config import Settings
from cbb.crypto import uid,sha,now,dumps,atomic_write
from cbb.service import Service,row
from cbb import db as D

target=root/'sensor-agent-data/agent.json'
if target.exists():
    print('Dedicated sensor already configured. Existing credentials retained.')
    raise SystemExit(0)
with exclusive(root/'data'):
    service=Service(Settings(data=root/'data',workers=False))
    with service.db.tx() as c:
        owner=row(c,select(D.users).where((D.users.c.role=='admin') & (D.users.c.active==True)).order_by(D.users.c.created_at))
        if not owner:raise RuntimeError('Finish dashboard first-time setup before local collection')
        cid=uid();token=secrets.token_urlsafe(32)
        c.execute(D.cases.insert().values(id=cid,title='Live endpoint monitoring',description='Real Windows event and firewall observations from this laptop. Collector intake is enabled; observations require analyst review.',owner_id=owner['id'],status='OPEN',severity=2,version=1,hold=True,created_at=now(),updated_at=now()))
        c.execute(D.enrollments.insert().values(id=uid(),token_hash=sha(token.encode()),name='Local Windows and WSL sensors',os='Windows',expires=time.time()+600,used=False))
        service.audit(c,'local-operator','LOCAL_SENSOR_SETUP',cid,reason='Owner requested real-time Windows and firewall collection')
    credentials=service.enroll(token)
    with service.db.tx() as c:
        c.execute(update(D.collectors).where(D.collectors.c.id==credentials['collector_id']).values(configuration=dumps({'paths':[],'channels':['System','Application'],'poll_seconds':5,'max_file_bytes':20971520,'intake_case_id':cid}),config_version=2))
        service.audit(c,'local-operator','COLLECTOR_CONFIGURED',credentials['collector_id'],details={'intake_case_id':cid,'channels':['System','Application']})
    config={**credentials,'server':'http://127.0.0.1:8765','data':str(target.parent),'enable_events':True,'enable_acquisitions':False,'allowed_paths':[],'allowed_channels':['System','Application','Security'],'firewall_files':[str(Path(os.environ['SystemRoot'])/'System32/LogFiles/Firewall/pfirewall.log')],'eve_files':[str(root/'sensor-data/eve.json')],'zeek_files':[]}
    atomic_write(target,json.dumps(config,indent=2).encode())
    service.db.engine.dispose()
    print(json.dumps({'state':'CONFIGURED','case_id':cid,'collector_id':credentials['collector_id'],'config':str(target),'secrets_printed':False}))
