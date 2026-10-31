"""Operator commands; run python -m cbb.cli --help."""
import argparse
import base64
import json
import os
import secrets
import shutil
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from .config import Settings
from .crypto import uid, now, sha, dumps, canon, atomic_write


@contextmanager
def exclusive(data):
    data.mkdir(parents=True,exist_ok=True)
    handle=(data/"server.lock").open("a+b")
    handle.seek(0);handle.write(b"0");handle.flush();handle.seek(0)
    try:
        if os.name=="nt":
            import msvcrt
            msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except OSError:
        handle.close();raise RuntimeError("This data directory is in use. Stop its server before an offline operation.")
    try:yield
    finally:handle.close()


def seed_demo(service):
    """Clearly labelled synthetic observations. Never runs tools against a target."""
    from argon2 import PasswordHasher
    from sqlalchemy import select,func
    from . import db as D
    from .service import row
    with service.db.read() as c:
        if c.execute(select(func.count()).select_from(D.users)).scalar():raise ValueError("Demo initialization requires an empty data directory; use --data demo-data")
    password=secrets.token_urlsafe(18);actor=uid();case_id=uid();token=secrets.token_urlsafe(32)
    with service.db.tx() as c:
        c.execute(D.users.insert().values(id=actor,username="demo-admin",password_hash=PasswordHasher().hash(password),role="admin",active=True,created_at=now()))
        c.execute(D.cases.insert().values(id=case_id,title="DEMO · Controlled endpoint investigation",description="Synthetic training observations; no real endpoint was accessed.",owner_id=actor,status="INVESTIGATING",severity=3,version=1,hold=True,created_at=now(),updated_at=now()))
        c.execute(D.enrollments.insert().values(id=uid(),token_hash=sha(token.encode()),name="DEMO workstation",os="fixture",expires=time.time()+600,used=False))
    credentials=service.enroll(token)
    with service.db.read() as c:collector=row(c,select(D.collectors).where(D.collectors.c.id==credentials["collector_id"]))
    stamp=now();items=[]
    observations=[("process.create",{"process":"demo-editor.exe","process_guid":"DEMO-1","severity":1,"summary":"DEMO · Editor process observed"}),("file.create",{"path":"demo/notes.txt","process_guid":"DEMO-1","severity":2,"summary":"DEMO · File creation observed"}),("network.connect",{"dst_ip":"192.0.2.10","process_guid":"DEMO-1","severity":2,"summary":"DEMO · Documentation address connection"}),("auth.failure",{"user":"demo-user","severity":3,"summary":"DEMO · Failed authentication fixture"}),("yara.match",{"path":"demo/benign-marker.txt","severity":3,"summary":"DEMO · Benign test marker matched a test rule"}),("log.clear",{"severity":4,"summary":"DEMO · Simulated log-clear observation"})]
    for n,(etype,body) in enumerate(observations,1):
        raw=canon(body);items.append({"boot_id":"demo-fixture-v1","source_seq":str(n),"source_type":"lab.fixture","event_type":etype,"collected_at":stamp,"original_timestamp":stamp,"raw_base64":base64.b64encode(raw).decode(),"raw_sha256":sha(raw)})
    accepted=service.accept(collector,items);service.seal_pending()
    with service.db.tx() as c:
        for item in accepted:c.execute(D.case_evidence.insert().values(id=uid(),case_id=case_id,evidence_id=item["evidence_id"],case_version=1,active=True,reason="Labelled demonstration dataset",created_at=stamp))
        service.audit(c,actor,"DEMO_INITIALIZED",case_id)
    for item in accepted:service.analyze(item["evidence_id"])
    service.checkpoint(actor)
    service.bootstrap_file.unlink(missing_ok=True)
    return {"username":"demo-admin","password":password,"case_id":case_id,"data":str(service.root),"note":"Synthetic data only. Password is generated uniquely; store it securely."}


def main(argv=None):
    p=argparse.ArgumentParser(description="Cyber Black Box operator tools")
    p.add_argument("--data",type=Path,help="Persistent data directory (default CBB_DATA or ./data)")
    s=p.add_subparsers(dest="command",required=True)
    serve=s.add_parser("serve",help="Start API, web interface and background worker")
    serve.add_argument("--host",default="127.0.0.1");serve.add_argument("--port",type=int,default=8765)
    s.add_parser("init",help="Initialize an empty installation and show setup token path")
    s.add_parser("demo",help="Initialize synthetic demo in an EMPTY data directory")
    v=s.add_parser("verify",help="Verify local evidence and optional external checkpoint");v.add_argument("--checkpoint",type=Path)
    v=s.add_parser("verify-package",help="Offline ZIP verification with separately trusted signing key");v.add_argument("package",type=Path);v.add_argument("--public-key",required=True)
    s.add_parser("checkpoint",help="Create a signed checkpoint while server is stopped")
    b=s.add_parser("backup",help="Offline consistent SQLite and archive backup");b.add_argument("destination",type=Path)
    r=s.add_parser("restore",help="Restore a backup into a new empty directory");r.add_argument("backup",type=Path);r.add_argument("--checkpoint",type=Path)
    s.add_parser("schema",help="Print ingest JSON Schema")
    a=p.parse_args(argv)
    try:
        if a.command=="verify-package":
            from .verify import verify_package
            result=verify_package(a.package,a.public_key);print(json.dumps(result,indent=2));return 0 if result["status"]=="VALID" else 2
        if a.command=="schema":
            from .schema import WireEvent
            print(json.dumps(WireEvent.model_json_schema(),indent=2));return 0
        settings=Settings()
        if a.data:settings.data=a.data.resolve()
        if a.command=="serve":
            from .api import create_app
            import uvicorn
            if settings.mode=="virtual" and a.host not in ("127.0.0.1","localhost","::1"):
                raise ValueError("Virtual Mode is loopback-only. Use the hardened Cloud Mode for remote access.")
            with exclusive(settings.data):uvicorn.run(create_app(settings),host=a.host,port=a.port,proxy_headers=False)
            return 0
        if a.command=="restore":
            if settings.data.exists() and any(settings.data.iterdir()):raise ValueError("Restore requires an empty target directory")
            manifest=json.loads((a.backup/"backup-manifest.json").read_text())
            for item in manifest["files"]:
                source=(a.backup/item["path"]).resolve()
                if not source.is_relative_to(a.backup.resolve()):raise ValueError("Unsafe backup path")
                if sha(source.read_bytes())!=item["sha256"]:raise ValueError("Backup hash mismatch: "+item["path"])
            shutil.copytree(a.backup,settings.data,dirs_exist_ok=True)
        from .service import Service
        with exclusive(settings.data):
            service=Service(settings)
            if a.command=="init":print(json.dumps({"data":str(service.root),"setup_token_file":str(service.bootstrap_file),"public_key":service.deployment["public_key"]},indent=2))
            elif a.command=="demo":print(json.dumps(seed_demo(service),indent=2))
            elif a.command in ("verify","restore"):
                result=service.verify(json.loads(a.checkpoint.read_bytes()) if a.checkpoint else None);print(json.dumps(result,indent=2));return 2 if result["status"]=="INVALID" else 0
            elif a.command=="checkpoint":print(json.dumps(service.checkpoint("operator-cli"),indent=2))
            elif a.command=="backup":
                if not service.db.sqlite:raise ValueError("PostgreSQL: use the documented pg_dump plus archive backup procedure")
                dest=a.destination.resolve()
                if dest.exists():raise ValueError("Backup destination must be new")
                if dest.is_relative_to(service.root):raise ValueError("Backup must be outside the live data directory")
                service.seal_pending(100000);service.checkpoint("operator-cli")
                if service.verify()["status"]=="INVALID":raise ValueError("Verify failed; backup cannot be labelled healthy")
                dest.mkdir(parents=True)
                for source in service.root.rglob("*"):
                    if source.is_file() and source.name not in ("cbb.sqlite3","cbb.sqlite3-wal","cbb.sqlite3-shm","server.lock"):
                        target=dest/source.relative_to(service.root);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
                with sqlite3.connect(service.root/"cbb.sqlite3") as source,sqlite3.connect(dest/"cbb.sqlite3") as target:source.backup(target)
                manifest={"created_at":now(),"deployment":service.deployment,"files":[{"path":str(f.relative_to(dest)).replace("\\","/"),"sha256":sha(f.read_bytes())} for f in dest.rglob("*") if f.is_file()]}
                atomic_write(dest/"backup-manifest.json",canon(manifest));print(json.dumps({"backup":str(dest),"files":len(manifest["files"]),"contains_private_keys":True},indent=2))
            service.db.engine.dispose()
        return 0
    except (ValueError,RuntimeError,OSError,KeyError) as ex:
        print("Error: "+str(ex),file=sys.stderr);return 2


if __name__=="__main__":raise SystemExit(main())
