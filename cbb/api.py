import asyncio
import base64
import hashlib
import io
import json
import logging
import os
import secrets
import shutil
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, unquote
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
import pyotp
from fastapi import FastAPI, Request, Response, Depends, Query, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, update, delete, func, and_, or_
from . import db as D
from .crypto import uid, now, sha, file_sha, canon, dumps, loads, strict_json, atomic_write, verify_signature
from .service import Service, DomainError, row, rows
from .config import Settings

log=logging.getLogger("cbb")
passwords=PasswordHasher()

def public_user(user):return {k:user[k] for k in ("id","username","role","active")}

def create_app(settings=None):
    service=Service(settings)
    stop=threading.Event()
    worker_errors={"last_error":None,"last_tick":None}

    def worker():
        while not stop.is_set():
            try:
                service.tick();worker_errors["last_tick"]=now();worker_errors["last_error"]=None
            except Exception as ex:
                log.exception("Worker tick failed")
                worker_errors["last_error"]=type(ex).__name__+": "+str(ex)[:200]
            stop.wait(.5)

    def background_worker():
        while not stop.is_set():
            try:service.tick(background=True)
            except Exception:log.exception("Background task failed")
            stop.wait(1)

    def anchor_worker():
        while not stop.is_set():
            try:service.maintenance()
            except Exception:log.exception("Periodic anchoring/scheduling failed")
            stop.wait(5)

    @asynccontextmanager
    async def lifespan(app):
        service.recover_jobs()
        thread=None;maintenance=None;anchors=None
        if service.settings.workers:
            thread=threading.Thread(target=worker,daemon=True);thread.start()
            maintenance=threading.Thread(target=background_worker,daemon=True);maintenance.start()
            anchors=threading.Thread(target=anchor_worker,daemon=True);anchors.start()
        yield
        stop.set()
        if thread:thread.join(timeout=10)
        if maintenance:maintenance.join(timeout=10)
        if anchors:anchors.join(timeout=10)

    app=FastAPI(title="Cyber Black Box",version="0.1.0",lifespan=lifespan,docs_url="/api/docs" if service.settings.mode=="virtual" else None,openapi_url="/api/openapi.json" if service.settings.mode=="virtual" else None)
    app.state.service=service
    throttle={};throttle_lock=threading.Lock()

    def rate(key,maximum=20,seconds=60):
        with throttle_lock:
            current=time.monotonic();values=[t for t in throttle.get(key,[]) if t>current-seconds]
            if len(values)>=maximum:raise DomainError("RATE_LIMIT","Too many requests; retry later",429)
            values.append(current);throttle[key]=values
            if len(throttle)>10000:throttle.clear()

    @app.exception_handler(DomainError)
    async def domain_error(request,exc):
        return JSONResponse({"type":"about:blank","title":exc.message,"detail":exc.message,"status":exc.status,"code":exc.code,"request_id":getattr(request.state,"request_id",None),"retryable":exc.status in (429,503)},status_code=exc.status,media_type="application/problem+json")

    @app.middleware("http")
    async def guard(request,call_next):
        request.state.request_id=uid()
        if request.method not in ("GET","HEAD","OPTIONS"):
            origin=request.headers.get("origin")
            if origin and origin.rstrip("/")!=service.settings.public_url.rstrip("/"):
                return JSONResponse({"detail":"Origin not allowed","code":"ORIGIN_DENIED"},403)
            limit=5*1024**2 if "/chunks/" in request.url.path else (260*1024**2 if request.url.path.endswith("/pcaps") else 2*1024**2)
            try: content_length=int(request.headers.get("content-length","0") or 0)
            except ValueError:return JSONResponse({"detail":"Invalid content length"},400)
            if content_length>limit:return JSONResponse({"detail":"Request too large"},413)
            if request.url.path.endswith("/pcaps") and content_length<=0:return JSONResponse({"detail":"PCAP upload requires Content-Length"},411)
            if not request.url.path.endswith("/pcaps"):
                body=bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body)>limit:return JSONResponse({"detail":"Request too large"},413)
                request._body=bytes(body)
                if "application/json" in request.headers.get("content-type","") and body:
                    try:strict_json(body)
                    except (ValueError,UnicodeError):return JSONResponse({"detail":"Invalid or duplicate-key JSON"},400)
        response=await call_next(request)
        response.headers["X-Request-ID"]=request.state.request_id
        response.headers["X-Content-Type-Options"]="nosniff"
        response.headers["X-Frame-Options"]="DENY"
        response.headers["Referrer-Policy"]="no-referrer"
        response.headers["Content-Security-Policy"]="default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'"
        if request.url.path.startswith("/api/"):response.headers["Cache-Control"]="no-store"
        return response

    def user(request:Request):
        token=request.cookies.get("cbb_session","")
        with service.db.tx() as c:
            session=row(c,select(D.sessions).where(D.sessions.c.token_hash==sha(token.encode()))) if token else None
            if not session or time.time()-session["created"]>28800 or time.time()-session["last_seen"]>1800:raise DomainError("UNAUTHENTICATED","Sign in required",401)
            u=row(c,select(D.users).where(D.users.c.id==session["user_id"]))
            if not u or not u["active"]:raise DomainError("UNAUTHENTICATED","Account unavailable",401)
            if request.method not in ("GET","HEAD") and not secrets.compare_digest(request.headers.get("x-csrf-token",""),session["csrf"]):raise DomainError("CSRF","Refresh your session and retry",403)
            c.execute(update(D.sessions).where(D.sessions.c.id==session["id"]).values(last_seen=time.time()))
            u["csrf"]=session["csrf"];return u

    def admin(u=Depends(user)):
        if u["role"]!="admin":raise DomainError("FORBIDDEN","Administrator role required",403)
        return u

    def investigator(u=Depends(user)):
        if u["role"] not in ("investigator","admin"):raise DomainError("FORBIDDEN","Investigator role required",403)
        return u

    def collector(request:Request):
        auth=request.headers.get("authorization","")
        token=auth[7:] if auth.startswith("Bearer ") else ""
        with service.db.read() as c:col=row(c,select(D.collectors).where(D.collectors.c.token_hash==sha(token.encode()))) if token else None
        if not col or col["state"]!="ACTIVE":raise DomainError("COLLECTOR_AUTH","Collector credential invalid",401)
        if service.settings.require_mtls:
            if not secrets.compare_digest(request.headers.get("x-proxy-secret",""),service.settings.proxy_secret):raise DomainError("MTLS_REQUIRED","Authenticated client certificate required",401)
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            try:fp=x509.load_pem_x509_certificate(unquote(request.headers["x-client-cert"]).encode()).fingerprint(hashes.SHA256()).hex()
            except Exception:raise DomainError("MTLS_REQUIRED","Client certificate unavailable",401)
            if not col["cert_fingerprint"] or not secrets.compare_digest(fp,col["cert_fingerprint"]):raise DomainError("CERT_MISMATCH","Certificate not bound to this collector",403)
        return col

    def reauthenticate(u,password,otp=None):
        try:passwords.verify(u["password_hash"],password)
        except (VerificationError,TypeError):raise DomainError("REAUTHENTICATE","Password incorrect",403)
        if u.get("totp_secret") and not pyotp.TOTP(u["totp_secret"]).verify(otp or "",valid_window=0):raise DomainError("MFA_REQUIRED","Valid one-time code required",403)

    @app.get("/api/v1/status")
    def status():
        with service.db.read() as c:setup=c.execute(select(func.count()).select_from(D.users)).scalar()==0
        return {"setup_required":setup,"mode":service.settings.mode,"version":"0.1.0","public_key":service.deployment["public_key"],"deployment_id":service.deployment["id"]}

    @app.post("/api/v1/admin/setup")
    def setup(body:dict,request:Request):
        rate("setup:"+request.client.host,5)
        with service.db.tx() as c:
            if c.execute(select(func.count()).select_from(D.users)).scalar():raise DomainError("SETUP_COMPLETE","Setup already completed",409)
            if not service.bootstrap_file.exists() or not secrets.compare_digest(str(body.get("token","")),service.bootstrap_file.read_text().strip()):raise DomainError("BOOTSTRAP_TOKEN","Invalid setup token",403)
            name=str(body.get("username","")).strip();password=str(body.get("password",""))
            if len(name)<3 or len(name)>80 or len(password)<12 or len(password)>256:raise DomainError("INVALID_ACCOUNT","Username needs 3–80 characters and password 12–256 characters",422)
            userid=uid();c.execute(D.users.insert().values(id=userid,username=name,password_hash=passwords.hash(password),role="admin",active=True,created_at=now()))
            self_id=uid();c.execute(D.cases.insert().values(id=self_id,title="Initial investigation workspace",description="Assign an investigator account or add evidence explicitly. Administrator access does not expose all raw evidence.",owner_id=userid,status="OPEN",severity=2,version=1,hold=True,created_at=now(),updated_at=now()))
            service.audit(c,userid,"INITIAL_SETUP",service.deployment["id"])
        service.bootstrap_file.unlink(missing_ok=True)
        return {"created":True}

    @app.post("/api/v1/auth/session")
    def login(body:dict,request:Request,response:Response):
        rate("login:"+request.client.host,10)
        with service.db.tx() as c:
            u=row(c,select(D.users).where(D.users.c.username==str(body.get("username",""))))
            valid=False
            try:valid=bool(u and u["active"] and passwords.verify(u["password_hash"],str(body.get("password",""))))
            except VerificationError:pass
            if not valid:raise DomainError("LOGIN_FAILED","Invalid credentials",401)
            if u["totp_secret"]:
                counter=int(time.time())//30
                if not pyotp.TOTP(u["totp_secret"]).verify(str(body.get("otp","")),valid_window=0) or counter<=u["last_totp_counter"]:raise DomainError("LOGIN_FAILED","Invalid or reused verification code",401)
                c.execute(update(D.users).where(D.users.c.id==u["id"]).values(last_totp_counter=counter))
            token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(24)
            c.execute(D.sessions.insert().values(id=uid(),user_id=u["id"],token_hash=sha(token.encode()),csrf=csrf,created=time.time(),last_seen=time.time()))
            service.audit(c,u["id"],"LOGIN",u["id"])
        response.set_cookie("cbb_session",token,httponly=True,secure=service.settings.secure_cookies,samesite="strict",max_age=28800)
        return {"user":public_user(u),"csrf":csrf}

    @app.get("/api/v1/auth/me")
    def me(u=Depends(user)):return {"user":public_user(u),"csrf":u["csrf"]}

    @app.delete("/api/v1/auth/session")
    def logout(request:Request,response:Response,u=Depends(user)):
        with service.db.tx() as c:
            c.execute(delete(D.sessions).where(D.sessions.c.token_hash==sha(request.cookies.get("cbb_session","").encode())))
            service.audit(c,u["id"],"LOGOUT",u["id"])
        response.delete_cookie("cbb_session");return {"ok":True}

    @app.post("/api/v1/auth/mfa")
    def mfa(body:dict,u=Depends(user)):
        reauthenticate(u,str(body.get("password","")),body.get("current_otp"))
        secret=str(body.get("secret",""))
        if not secret:
            secret=pyotp.random_base32();return {"secret":secret,"uri":pyotp.TOTP(secret).provisioning_uri(u["username"],issuer_name="Cyber Black Box")}
        if not pyotp.TOTP(secret).verify(str(body.get("otp","")),valid_window=0):raise DomainError("MFA_INVALID","Verification code does not match",422)
        with service.db.tx() as c:
            c.execute(update(D.users).where(D.users.c.id==u["id"]).values(totp_secret=secret,last_totp_counter=-1))
            service.audit(c,u["id"],"MFA_ENABLED",u["id"])
        return {"enabled":True}

    @app.get("/api/v1/users")
    def list_users(u=Depends(user)):
        with service.db.read() as c:return rows(c,select(D.users.c.id,D.users.c.username,D.users.c.role,D.users.c.active))

    @app.post("/api/v1/users")
    def add_user(body:dict,u=Depends(admin)):
        name=str(body.get("username","")).strip();password=str(body.get("password",""));role=body.get("role")
        if len(name)<3 or len(name)>80 or not 12<=len(password)<=256 or role not in ("admin","investigator","reviewer","auditor"):raise DomainError("INVALID_ACCOUNT","Invalid username, password length or role",422)
        with service.db.tx() as c:
            if row(c,select(D.users).where(D.users.c.username==name)):raise DomainError("USERNAME_EXISTS","Username already exists",409)
            userid=uid();c.execute(D.users.insert().values(id=userid,username=name,password_hash=passwords.hash(password),role=role,active=True,created_at=now()))
            service.audit(c,u["id"],"USER_CREATED",userid,details={"role":role})
        return {"id":userid}

    @app.patch("/api/v1/users/{userid}")
    def change_user(userid:str,body:dict,u=Depends(admin)):
        if userid==u["id"]:raise DomainError("SELF_CHANGE","Use another administrator for your own role changes",409)
        values={}
        if body.get("role") in ("admin","investigator","reviewer","auditor"):values["role"]=body["role"]
        if isinstance(body.get("active"),bool):values["active"]=body["active"]
        if not values:raise DomainError("INVALID_CHANGE","No supported changes",422)
        with service.db.tx() as c:
            c.execute(update(D.users).where(D.users.c.id==userid).values(**values));c.execute(delete(D.sessions).where(D.sessions.c.user_id==userid));service.audit(c,u["id"],"USER_CHANGED",userid,details=values)
        return {"ok":True}

    @app.get("/api/v1/overview")
    def overview(u=Depends(user)):
        with service.db.read() as c:
            scope=service.scope_evidence(u);query=select(func.count()).select_from(D.evidence)
            if scope is not None:query=query.where(scope)
            count=c.execute(query).scalar()
            pending=c.execute(select(func.count()).select_from(D.receipts).where(D.receipts.c.state=="STAGED")).scalar()
            health=rows(c,select(D.collectors.c.id,D.collectors.c.name,D.collectors.c.last_heartbeat,D.collectors.c.state))
            case_query=select(func.count()).select_from(D.cases).where(or_(D.cases.c.owner_id==u["id"],D.cases.c.id.in_(select(D.case_members.c.case_id).where(D.case_members.c.user_id==u["id"]))))
            case_count=c.execute(case_query).scalar()
            latest=row(c,select(D.checkpoints.c.id,D.checkpoints.c.created_at).order_by(D.checkpoints.c.sequence.desc()).limit(1))
            groups=rows(c,select(D.evidence.c.source_type,func.count().label("count")).where(scope if scope is not None else True).group_by(D.evidence.c.source_type))
            receipts=rows(c,select(D.receipts.c.state,func.count().label("count")).group_by(D.receipts.c.state))
            verification=row(c,select(D.verifications).order_by(D.verifications.c.created_at.desc()).limit(1))
        disk=shutil.disk_usage(service.root)
        return {"evidence":count,"pending":pending,"cases":case_count,"collectors":health,"sources":groups,"receipts":receipts,"checkpoint":latest,"verification":loads(verification["result"]) if verification else None,"disk":{"free":disk.free,"total":disk.total},"worker":worker_errors,"mode":service.settings.mode,"witness_configured":bool(service.settings.witness_url),"witness_independent":service.settings.witness_independent}

    @app.post("/api/v1/enrollments")
    def enroll_token(body:dict,u=Depends(admin)):
        token=secrets.token_urlsafe(32);eid=uid()
        with service.db.tx() as c:
            c.execute(D.enrollments.insert().values(id=eid,token_hash=sha(token.encode()),name=str(body.get("name","Collector"))[:100],os=str(body.get("os","unknown"))[:40],expires=time.time()+600,used=False));service.audit(c,u["id"],"ENROLLMENT_ISSUED",eid)
        return {"token":token,"expires_in":600}

    @app.post("/api/v1/collectors/enroll")
    def enroll(body:dict,request:Request):
        rate("enroll:"+request.client.host,10)
        return service.enroll(str(body.get("token","")),str(body.get("name",""))[:100] or None)

    @app.get("/api/v1/collectors")
    def collectors(u=Depends(user)):
        with service.db.read() as c:
            result=rows(c,select(D.collectors))
            for r in result:
                r.pop("token_hash",None);r["health"]=loads(r["health"],{});r["configuration"]=loads(r["configuration"],{})
                r["online"]=bool(r["last_heartbeat"] and time.time()-datetime.fromisoformat(r["last_heartbeat"].replace("Z","+00:00")).timestamp()<90)
            return result

    @app.post("/api/v1/collectors/{collector_id}/revoke")
    def revoke(collector_id:str,u=Depends(admin)):
        with service.db.tx() as c:c.execute(update(D.collectors).where(D.collectors.c.id==collector_id).values(state="REVOKED"));service.audit(c,u["id"],"COLLECTOR_REVOKED",collector_id)
        return {"ok":True}

    @app.put("/api/v1/collectors/{collector_id}/configuration")
    def configure_collector(collector_id:str,body:dict,u=Depends(admin)):
        if not isinstance(body.get("paths",[]),list) or len(body.get("paths",[]))>50:raise DomainError("INVALID_CONFIG","Provide at most 50 watched paths",422)
        with service.db.tx() as c:
            col=row(c,select(D.collectors).where(D.collectors.c.id==collector_id))
            if not col:raise DomainError("NOT_FOUND","Collector not found",404)
            intake=body.get('intake_case_id',loads(col['configuration']).get('intake_case_id'))
            if intake:service.allowed_case(c,u,intake,write=True)
            conf={"paths":[str(x)[:500] for x in body.get("paths",[])],"channels":[str(x)[:100] for x in body.get("channels",["System"])],"poll_seconds":max(2,min(60,int(body.get("poll_seconds",5)))),"max_file_bytes":min(20971520,max(1024,int(body.get("max_file_bytes",20971520))))}
            conf['intake_case_id']=intake or None
            c.execute(update(D.collectors).where(D.collectors.c.id==collector_id).values(configuration=dumps(conf),config_version=col["config_version"]+1));service.audit(c,u["id"],"COLLECTOR_CONFIGURED",collector_id,details=conf)
        return {"ok":True}

    @app.post("/api/v1/collectors/{collector_id}/certificate")
    def bind_certificate(collector_id:str,body:dict,u=Depends(admin)):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        try:cert=x509.load_pem_x509_certificate(str(body["certificate"]).encode());fp=cert.fingerprint(hashes.SHA256()).hex()
        except Exception:raise DomainError("INVALID_CERTIFICATE","Provide a PEM client certificate",422)
        with service.db.tx() as c:
            c.execute(update(D.collectors).where(D.collectors.c.id==collector_id).values(cert_fingerprint=fp));service.audit(c,u["id"],"CERTIFICATE_BOUND",collector_id,details={"fingerprint":fp})
        return {"fingerprint":fp}

    @app.post("/api/v1/collectors/heartbeat")
    def heartbeat(body:dict,col=Depends(collector)):
        with service.db.tx() as c:
            current=row(c,select(D.collectors).where(D.collectors.c.id==col["id"]))
            if current["last_heartbeat"] and time.time()-datetime.fromisoformat(current["last_heartbeat"].replace("Z","+00:00")).timestamp()>90:service.audit(c,col["id"],"COLLECTION_GAP",col["id"],details={"last_heartbeat":current["last_heartbeat"],"reconnected_at":now()})
            c.execute(update(D.collectors).where(D.collectors.c.id==col["id"]).values(last_heartbeat=now(),health=dumps(body)))
            return {"server_time":now(),"config_version":current["config_version"],"configuration":loads(current["configuration"]),"signed_configuration":service.signed("CBB-CONFIG-v1",{"collector_id":col["id"],"version":current["config_version"],"configuration":loads(current["configuration"])})}

    @app.post("/api/v1/ingest/events",status_code=202)
    def ingest(body:dict,col=Depends(collector)):
        rate("ingest:"+col["id"],120)
        if len(canon(body))>service.settings.max_batch_bytes:raise DomainError("TOO_LARGE","Batch exceeds 1 MiB",413)
        return {"batch_id":body.get("batch_id"),"items":service.accept(col,body.get("events",[]))}

    @app.get("/api/v1/receipts/{receipt_id}")
    def receipt(receipt_id:str,col=Depends(collector)):
        with service.db.read() as c:r=row(c,select(D.receipts.c.id,D.receipts.c.state,D.receipts.c.evidence_id,D.receipts.c.error).where(and_(D.receipts.c.id==receipt_id,D.receipts.c.collector_id==col["id"])))
        if not r:raise DomainError("NOT_FOUND","Receipt not found",404)
        return r

    @app.get("/api/v1/evidence")
    def evidence(q:str="",source:str="",asset:str="",start:str="",end:str="",cursor:int=0,snapshot:int=0,limit:int=Query(50,ge=1,le=200),u=Depends(user)):
        with service.db.tx() as c:
            head=service.chain(c,"evidence")["head_sequence"];snapshot=snapshot or head
            query=select(D.evidence.c.id,D.evidence.c.sequence,D.evidence.c.asset_id,D.evidence.c.source_type,D.evidence.c.event_type,D.evidence.c.occurred_at,D.evidence.c.received_at,D.evidence.c.severity,D.evidence.c.summary).where(and_(D.evidence.c.sequence>cursor,D.evidence.c.sequence<=snapshot))
            scope=service.scope_evidence(u)
            if scope is not None:query=query.where(scope)
            if q:query=query.where(or_(D.evidence.c.summary.contains(q[:200],autoescape=True),D.evidence.c.event_type.contains(q[:200],autoescape=True),D.evidence.c.id==q,D.evidence.c.raw_sha256==q))
            if source:query=query.where(D.evidence.c.source_type==source)
            if asset:query=query.where(D.evidence.c.asset_id==asset)
            if start:query=query.where(D.evidence.c.received_at>=start)
            if end:query=query.where(D.evidence.c.received_at<=end)
            result=rows(c,query.order_by(D.evidence.c.sequence).limit(limit+1));more=len(result)>limit;result=result[:limit]
            service.audit(c,u["id"],"EVIDENCE_SEARCH","query",details={"q":q[:200],"snapshot":str(snapshot),"returned_ids":[r["id"] for r in result]})
            return {"items":result,"snapshot":snapshot,"next_cursor":result[-1]["sequence"] if more else None}

    @app.get("/api/v1/evidence/{eid}")
    def detail(eid:str,u=Depends(user)):
        with service.db.tx() as c:
            item=service.visible_evidence(c,u,eid);item["envelope"]=loads(item["envelope"])
            service.audit(c,u["id"],"EVIDENCE_VIEW",eid)
            return item

    @app.get("/api/v1/evidence/{eid}/raw")
    def raw(eid:str,u=Depends(user)):
        with service.db.tx() as c:
            item=service.visible_evidence(c,u,eid)
            if u["role"]=="auditor":raise DomainError("FORBIDDEN","Auditor cannot download raw evidence",403)
            service.audit(c,u["id"],"RAW_ACCESS",eid)
            try:data=service.read_raw(c,item)
            except OSError:raise DomainError("RAW_UNAVAILABLE","Raw evidence unavailable",503)
            if sha(data)!=item["raw_sha256"]:raise DomainError("RAW_MODIFIED","Raw evidence hash mismatch",409)
        return Response(data,media_type="application/octet-stream",headers={"Content-Disposition":f'attachment; filename="{eid}.raw"',"X-Content-SHA256":sha(data)})

    @app.get("/api/v1/cases")
    def cases(u=Depends(user)):
        with service.db.read() as c:return rows(c,select(D.cases).where(or_(D.cases.c.owner_id==u["id"],D.cases.c.id.in_(select(D.case_members.c.case_id).where(D.case_members.c.user_id==u["id"])))) .order_by(D.cases.c.updated_at.desc()))

    @app.post("/api/v1/cases")
    def create_case(body:dict,u=Depends(investigator)):
        title=str(body.get("title","")).strip()
        if not 3<=len(title)<=200:raise DomainError("CASE_TITLE","Title requires 3–200 characters",422)
        cid=uid()
        with service.db.tx() as c:
            c.execute(D.cases.insert().values(id=cid,title=title,description=str(body.get("description",""))[:10000],owner_id=u["id"],status="OPEN",severity=max(1,min(5,int(body.get("severity",2)))),version=1,hold=True,created_at=now(),updated_at=now()));service.audit(c,u["id"],"CASE_CREATED",cid)
        return {"id":cid}

    @app.get("/api/v1/cases/{cid}")
    def case_detail(cid:str,u=Depends(user)):
        with service.db.tx() as c:
            case=service.allowed_case(c,u,cid)
            case["evidence"]=rows(c,select(D.evidence.c.id,D.evidence.c.sequence,D.evidence.c.summary,D.evidence.c.source_type,D.evidence.c.occurred_at).join(D.case_evidence,D.case_evidence.c.evidence_id==D.evidence.c.id).where(and_(D.case_evidence.c.case_id==cid,D.case_evidence.c.active==True)))
            case["notes"]=rows(c,select(D.notes).where(D.notes.c.case_id==cid).order_by(D.notes.c.created_at));case["members"]=rows(c,select(D.case_members).where(D.case_members.c.case_id==cid))
            service.audit(c,u["id"],"CASE_VIEW",cid);return case

    @app.patch("/api/v1/cases/{cid}")
    def change_case(cid:str,body:dict,u=Depends(investigator)):
        with service.db.tx() as c:
            case=service.allowed_case(c,u,cid,True)
            if body.get("version")!=case["version"]:raise DomainError("VERSION_CONFLICT","Case changed; refresh before saving",409)
            values={k:body[k] for k in ("title","description","status","conclusion","hold") if k in body}
            if "status" in values and values["status"] not in ("OPEN","TRIAGE","INVESTIGATING","REVIEW","CLOSED"):raise DomainError("STATUS","Unknown status",422)
            if values.get("status")=="CLOSED" and not str(values.get("conclusion") or case["conclusion"] or "").strip():raise DomainError("CONCLUSION","A conclusion is required before closing",422)
            if "hold" in values and not isinstance(values["hold"],bool):raise DomainError("HOLD","Hold must be true or false",422)
            values.update(version=case["version"]+1,updated_at=now());c.execute(update(D.cases).where(D.cases.c.id==cid).values(**values));service.audit(c,u["id"],"CASE_UPDATED",cid,details=values)
        return {"version":values["version"]}

    @app.post("/api/v1/cases/{cid}/members")
    def member(cid:str,body:dict,u=Depends(investigator)):
        with service.db.tx() as c:
            case=service.allowed_case(c,u,cid,True)
            if case["owner_id"]!=u["id"]:raise DomainError("OWNER_REQUIRED","Only the case owner can share access",403)
            member_id=str(body.get("user_id",""))
            if not row(c,select(D.users).where(D.users.c.id==member_id)):raise DomainError("NOT_FOUND","User not found",404)
            if not row(c,select(D.case_members).where(and_(D.case_members.c.case_id==cid,D.case_members.c.user_id==member_id))):c.execute(D.case_members.insert().values(case_id=cid,user_id=member_id))
            service.audit(c,u["id"],"CASE_SHARED",cid,details={"user_id":member_id})
        return {"ok":True}

    @app.post("/api/v1/cases/{cid}/evidence")
    def add_evidence(cid:str,body:dict,u=Depends(investigator)):
        ids=body.get("evidence_ids",[])
        if not ids or len(ids)>200:raise DomainError("SELECTION","Select between 1 and 200 records",422)
        with service.db.tx() as c:
            case=service.allowed_case(c,u,cid,True)
            for eid in ids:
                service.visible_evidence(c,u,eid)
                old=row(c,select(D.case_evidence).where(and_(D.case_evidence.c.case_id==cid,D.case_evidence.c.evidence_id==eid,D.case_evidence.c.active==True)))
                if not old:c.execute(D.case_evidence.insert().values(id=uid(),case_id=cid,evidence_id=eid,case_version=case["version"]+1,active=True,reason=str(body.get("reason","Investigator selection"))[:500],created_at=now()))
            c.execute(update(D.cases).where(D.cases.c.id==cid).values(version=case["version"]+1,updated_at=now()));service.audit(c,u["id"],"CASE_EVIDENCE_ADDED",cid,details={"ids":ids})
        return {"ok":True}

    @app.post("/api/v1/cases/{cid}/notes")
    def note(cid:str,body:dict,u=Depends(user)):
        text=str(body.get("body","")).strip()
        if not text or len(text)>10000:raise DomainError("NOTE","Note must contain 1–10000 characters",422)
        with service.db.tx() as c:
            service.allowed_case(c,u,cid)
            if u["role"]=="auditor":raise DomainError("FORBIDDEN","Auditor is read-only",403)
            previous=body.get("previous_id")
            if previous:
                old=row(c,select(D.notes).where(and_(D.notes.c.id==previous,D.notes.c.case_id==cid)))
                if not old or old["author_id"]!=u["id"]:raise DomainError("NOTE_REVISION","Can only revise your own note in this case",403)
            nid=uid();c.execute(D.notes.insert().values(id=nid,case_id=cid,author_id=u["id"],body=text,previous_id=previous,created_at=now()));service.audit(c,u["id"],"NOTE_ADDED",cid,details={"note_id":nid})
        return {"id":nid}

    @app.post("/api/v1/cases/{cid}/evidence/{eid}/remove")
    def remove_evidence(cid:str,eid:str,body:dict,u=Depends(investigator)):
        reason=str(body.get("reason",""))[:2000].strip()
        if not reason:raise DomainError("REASON","Explain why this evidence is removed from the case",422)
        with service.db.tx() as c:
            case=service.allowed_case(c,u,cid,True)
            if body.get("version")!=case["version"]:raise DomainError("VERSION_CONFLICT","Case changed; refresh before saving",409)
            c.execute(update(D.case_evidence).where(and_(D.case_evidence.c.case_id==cid,D.case_evidence.c.evidence_id==eid,D.case_evidence.c.active==True)).values(active=False))
            c.execute(update(D.cases).where(D.cases.c.id==cid).values(version=case["version"]+1,updated_at=now()))
            service.audit(c,u["id"],"CASE_EVIDENCE_REMOVED",cid,reason=reason,details={"evidence_id":eid,"version":case["version"]+1})
        return {"version":case["version"]+1}

    @app.delete("/api/v1/cases/{cid}/members/{member_id}")
    def unshare(cid:str,member_id:str,u=Depends(investigator)):
        with service.db.tx() as c:
            case=service.allowed_case(c,u,cid,True)
            if case["owner_id"]!=u["id"]:raise DomainError("OWNER_REQUIRED","Only the owner can revoke sharing",403)
            c.execute(delete(D.case_members).where(and_(D.case_members.c.case_id==cid,D.case_members.c.user_id==member_id)))
            service.audit(c,u["id"],"CASE_ACCESS_REVOKED",cid,details={"user_id":member_id})
        return {"ok":True}

    @app.get("/api/v1/saved-views")
    def get_views(u=Depends(user)):
        with service.db.read() as c:
            r=row(c,select(D.config).where(D.config.c.id=="views:"+u["id"]))
            return {"version":r["version"] if r else 0,"views":loads(r["value"]) if r else []}

    @app.put("/api/v1/saved-views")
    def save_views(body:dict,u=Depends(user)):
        views=body.get("views",[])
        if not isinstance(views,list) or len(views)>30 or len(canon(views))>20000:raise DomainError("VIEWS","At most 30 views, totalling 20 KB",422)
        with service.db.tx() as c:
            key="views:"+u["id"];old=row(c,select(D.config).where(D.config.c.id==key));version=old["version"] if old else 0
            if body.get("version")!=version:raise DomainError("VERSION_CONFLICT","Views changed; refresh",409)
            values={"value":dumps(views),"version":version+1,"updated_at":now()}
            if old:c.execute(update(D.config).where(D.config.c.id==key).values(**values))
            else:c.execute(D.config.insert().values(id=key,**values))
        return {"version":version+1,"views":views}

    @app.get("/api/v1/alerts")
    def alert_list(u=Depends(user)):
        with service.db.read() as c:
            scope=service.scope_evidence(u)
            query=select(D.alerts).join(D.evidence,D.evidence.c.id==D.alerts.c.evidence_id)
            if scope is not None:query=query.where(scope)
            result=rows(c,query.order_by(D.alerts.c.risk.desc()).limit(200))
            for r in result:r["components"]=loads(r["components"],{})
            return result

    @app.post("/api/v1/alerts/{aid}/decisions")
    def alert_decision(aid:str,body:dict,u=Depends(investigator)):
        if body.get("status") not in ("ACKNOWLEDGED","INVESTIGATING","DISMISSED","RESOLVED") or not body.get("reason"):raise DomainError("DECISION","Select a status and provide a reason",422)
        with service.db.tx() as c:
            a=row(c,select(D.alerts).where(D.alerts.c.id==aid))
            if not a:raise DomainError("NOT_FOUND","Alert not found",404)
            service.visible_evidence(c,u,a["evidence_id"]);c.execute(update(D.alerts).where(D.alerts.c.id==aid).values(status=body["status"],decision=dumps({"actor":u["id"],"reason":str(body["reason"])[:2000],"at":now()})));service.audit(c,u["id"],"ALERT_DECISION",a["evidence_id"],reason=str(body["reason"])[:2000],details={"alert_id":aid,"status":body["status"]})
        return {"ok":True}

    @app.get("/api/v1/incidents")
    def incident_list(u=Depends(user)):
        with service.db.read() as c:
            result=[]
            for inc in rows(c,select(D.incidents).order_by(D.incidents.c.created_at.desc()).limit(200)):
                ids=loads(inc["evidence_ids"])
                try:
                    for eid in ids:service.visible_evidence(c,u,eid)
                except DomainError:continue
                inc["evidence_ids"]=ids;inc["decisions"]=loads(inc["decisions"],[]);result.append(inc)
            return result

    @app.post("/api/v1/incidents/{iid}/decisions")
    def incident_decision(iid:str,body:dict,u=Depends(investigator)):
        with service.db.tx() as c:
            inc=row(c,select(D.incidents).where(D.incidents.c.id==iid))
            if not inc:raise DomainError("NOT_FOUND","Incident not found",404)
            for eid in loads(inc["evidence_ids"]):service.visible_evidence(c,u,eid)
            decisions=loads(inc["decisions"],[]);decisions.append({"actor":u["id"],"decision":str(body.get("decision","reviewed"))[:50],"reason":str(body.get("reason",""))[:2000],"at":now()})
            c.execute(update(D.incidents).where(D.incidents.c.id==iid).values(decisions=dumps(decisions),version=inc["version"]+1));service.audit(c,u["id"],"INCIDENT_DECISION",iid,details=decisions[-1])
        return {"ok":True}

    @app.post("/api/v1/incidents/reshape")
    def reshape_incidents(body:dict,u=Depends(investigator)):
        ids=body.get("incident_ids",[]);groups=body.get("groups",[]);reason=str(body.get("reason",""))[:2000].strip()
        if not isinstance(ids,list) or not 1<=len(ids)<=20 or not isinstance(groups,list) or not 1<=len(groups)<=20 or not reason:raise DomainError("RESHAPE","Provide source incident IDs, evidence groups and a reason",422)
        with service.db.tx() as c:
            source=[];available=set()
            for iid in ids:
                inc=row(c,select(D.incidents).where(D.incidents.c.id==iid))
                if not inc:raise DomainError("NOT_FOUND","Incident not found",404)
                source.append(inc)
                for eid in loads(inc["evidence_ids"]):service.visible_evidence(c,u,eid);available.add(eid)
            flat=[]
            for group in groups:
                if not isinstance(group,list) or not group:raise DomainError("GROUPS","Each group must contain evidence IDs",422)
                flat.extend(group)
            if len(flat)!=len(set(flat)) or set(flat)!=available:raise DomainError("GROUPS","Groups must partition all source evidence exactly once",422)
            created=[]
            for index,group in enumerate(groups):
                iid=uid();decision={"actor":u["id"],"decision":"MANUAL_GROUP","reason":reason,"source_incidents":ids,"at":now()}
                c.execute(D.incidents.insert().values(id=iid,asset_id=source[0]["asset_id"],title=(str(body.get("title","Analyst grouping"))[:120]+(" · "+str(index+1) if len(groups)>1 else "")),confidence=min(r["confidence"] for r in source),rule_id="manual/1.0",version=1,evidence_ids=dumps(group),decisions=dumps([decision]),created_at=now(),dedup_key="manual:"+iid));created.append(iid)
            for inc in source:
                decisions=loads(inc["decisions"],[])+[{"actor":u["id"],"decision":"REGROUPED","reason":reason,"derived_incidents":created,"at":now()}]
                c.execute(update(D.incidents).where(D.incidents.c.id==inc["id"]).values(decisions=dumps(decisions),version=inc["version"]+1))
                service.audit(c,u["id"],"INCIDENT_REGROUPED",inc["id"],reason=reason,details={"derived_incidents":created})
        return {"incident_ids":created}

    @app.get("/api/v1/custody")
    def custody_list(target:str="",u=Depends(user)):
        with service.db.tx() as c:
            if u["role"] not in ("admin","auditor"):
                if not target:raise DomainError("TARGET_REQUIRED","Choose a case or evidence record",422)
                try:service.allowed_case(c,u,target)
                except DomainError:service.visible_evidence(c,u,target)
            query=select(D.custody).order_by(D.custody.c.sequence.desc()).limit(200)
            if target:query=query.where(D.custody.c.target==target)
            result=rows(c,query)
            for r in result:r["envelope"]=loads(r["envelope"])
            service.audit(c,u["id"],"CUSTODY_VIEW",target or "all");return result

    @app.get("/api/v1/checkpoints")
    def cp_list(u=Depends(user)):
        with service.db.read() as c:
            result=rows(c,select(D.checkpoints).order_by(D.checkpoints.c.sequence.desc()).limit(100))
            for cp in result:cp["document"]=loads(cp["document"]);cp["witness"]=row(c,select(D.witness_receipts).where(D.witness_receipts.c.checkpoint_id==cp["id"]))
            return result

    @app.post("/api/v1/checkpoints")
    def new_cp(u=Depends(admin)):return service.checkpoint(u["id"])

    @app.post("/api/v1/verification-runs",status_code=202)
    def verify(body:dict,request:Request,u=Depends(admin)):
        payload={"checkpoint":body.get("checkpoint")}
        with service.db.tx() as c:jid=service.create_job(c,"verify",u["id"],payload,operation_key=u["id"]+":verify:"+request.headers.get("idempotency-key",uid()));service.audit(c,u["id"],"VERIFICATION_REQUESTED",jid)
        return {"job_id":jid}

    @app.get("/api/v1/verification-runs")
    def verifications(u=Depends(user)):
        with service.db.read() as c:return [{**r,"result":loads(r["result"])} for r in rows(c,select(D.verifications).order_by(D.verifications.c.created_at.desc()).limit(50))]

    @app.get("/api/v1/jobs")
    def jobs(u=Depends(user)):
        with service.db.read() as c:
            query=select(D.jobs).where(D.jobs.c.kind!="analyze").order_by(D.jobs.c.created_at.desc()).limit(100)
            if u["role"]!="admin":query=query.where(D.jobs.c.actor_id==u["id"])
            result=rows(c,query)
            for r in result:r["result"]=loads(r["result"],{});r["payload"]=loads(r["payload"],{})
            return result

    @app.post("/api/v1/jobs/{jid}/retry")
    def retry(jid:str,u=Depends(user)):
        with service.db.tx() as c:
            job=row(c,select(D.jobs).where(D.jobs.c.id==jid))
            if not job or (u["role"]!="admin" and job["actor_id"]!=u["id"]):raise DomainError("NOT_FOUND","Job not found",404)
            if job["state"]!="FAILED":raise DomainError("STATE","Only failed jobs can be retried",409)
            c.execute(update(D.jobs).where(D.jobs.c.id==jid).values(state="QUEUED",attempts=0,next_attempt=0,updated_at=now()));service.audit(c,u["id"],"JOB_RETRIED",jid)
        return {"ok":True}

    @app.post("/api/v1/exports",status_code=202)
    def export(body:dict,request:Request,u=Depends(investigator)):
        cid=str(body.get("case_id",""))
        with service.db.tx() as c:
            case=service.allowed_case(c,u,cid)
            ids=[r["evidence_id"] for r in rows(c,select(D.case_evidence).where(and_(D.case_evidence.c.case_id==cid,D.case_evidence.c.active==True)))]
            if not ids:raise DomainError("EMPTY_CASE","Add evidence before exporting",422)
            notes=rows(c,select(D.notes).where(D.notes.c.case_id==cid).order_by(D.notes.c.created_at))
            ai=rows(c,select(D.ai_runs).where(D.ai_runs.c.case_id==cid).order_by(D.ai_runs.c.created_at))
            jid=service.create_job(c,"export",u["id"],{"evidence_ids":ids,"case_version":case["version"],"case_snapshot":case,"notes_snapshot":notes,"ai_snapshot":ai},cid,operation_key=u["id"]+":export:"+request.headers.get("idempotency-key",uid()));service.audit(c,u["id"],"EXPORT_REQUESTED",cid)
        return {"job_id":jid}

    @app.get("/api/v1/exports")
    def export_list(u=Depends(user)):
        with service.db.read() as c:
            result=[]
            for ex in rows(c,select(D.exports).order_by(D.exports.c.created_at.desc()).limit(100)):
                try:service.allowed_case(c,u,ex["case_id"])
                except DomainError:continue
                ex.pop("manifest");ex.pop("path");result.append(ex)
            return result

    @app.get("/api/v1/exports/{eid}/download")
    def download_export(eid:str,u=Depends(user)):
        with service.db.tx() as c:
            ex=row(c,select(D.exports).where(D.exports.c.id==eid))
            if not ex:raise DomainError("NOT_FOUND","Package not found",404)
            service.allowed_case(c,u,ex["case_id"])
            if u["role"]=="auditor":raise DomainError("FORBIDDEN","Auditor cannot export evidence",403)
            path=service.root/ex["path"]
            if file_sha(path)!=ex["sha256"]:raise DomainError("PACKAGE_MODIFIED","Export package checksum mismatch",409)
            service.audit(c,u["id"],"EXPORT_DOWNLOAD_STARTED",ex["case_id"],details={"package_id":eid,"sha256":ex["sha256"]})
        return FileResponse(path,filename="case-"+eid+".zip",media_type="application/zip")

    @app.get("/api/v1/models")
    def model_list(u=Depends(user)):
        with service.db.read() as c:return [{**r,"manifest":loads(r["manifest"])} for r in rows(c,select(D.models).order_by(D.models.c.created_at.desc()))]

    @app.post("/api/v1/models/{operation}",status_code=202)
    def model_operation(operation:str,body:dict,u=Depends(admin)):
        if operation not in ("train","score"):raise DomainError("OPERATION","Use train or score",404)
        if operation=="train" and not body.get("confirm_benign"):raise DomainError("TRAINING_SCOPE","Confirm that the selected training range contains only reviewed benign activity",422)
        body={**body,"actor_id":u["id"]}
        with service.db.tx() as c:jid=service.create_job(c,operation,u["id"],body);service.audit(c,u["id"],"MODEL_"+operation.upper(),jid)
        return {"job_id":jid}

    @app.get("/api/v1/admin/diagnostics")
    def diagnostics(u=Depends(admin)):
        with service.db.read() as c:
            quarantined=rows(c,select(D.receipts.c.id,D.receipts.c.source_seq,D.receipts.c.error,D.receipts.c.received_at).where(D.receipts.c.state=="QUARANTINED").limit(100))
            config=rows(c,select(D.config).where(D.config.c.id!="deployment"))
        return {"mode":service.settings.mode,"database":"sqlite" if service.db.sqlite else "postgresql","worker":worker_errors,"quarantined":quarantined,"configuration":config,"integrations":{"yara":True,"suricata":bool(shutil.which("suricata")),"s3":bool(service.settings.s3_bucket),"signer":"remote" if service.settings.signer_url else "local","witness":bool(service.settings.witness_url)},"data_directory":str(service.root),"disk_free":shutil.disk_usage(service.root).free}

    @app.post("/api/v1/admin/replicate",status_code=202)
    def replicate(u=Depends(admin)):
        with service.db.tx() as c:return {"job_id":service.create_job(c,"replicate",u["id"],{})}

    @app.post("/api/v1/admin/quarantine/{rid}/replay")
    def replay(rid:str,u=Depends(admin)):
        with service.db.tx() as c:
            r=row(c,select(D.receipts).where(D.receipts.c.id==rid))
            if not r or r["state"]!="QUARANTINED":raise DomainError("STATE","Receipt is not quarantined",409)
            c.execute(update(D.receipts).where(D.receipts.c.id==rid).values(state="STAGED",error=None));service.audit(c,u["id"],"QUARANTINE_REPLAY",rid)
        return {"ok":True}

    @app.get("/health/live")
    def live():return {"status":"alive"}

    @app.get("/health/ready")
    def ready():
        with service.db.read() as c:c.execute(select(D.chains.c.id)).first()
        if shutil.disk_usage(service.root).free<50*1024**2:raise DomainError("CAPACITY","Low disk space",503)
        return {"status":"ready"}

    from .acquisition import register_acquisition_routes
    register_acquisition_routes(app,service,user,admin,investigator,collector,reauthenticate)
    from .integrations import register_import_routes
    register_import_routes(app,service,admin)
    from .upgrades import register_upgrade_routes
    register_upgrade_routes(app,service,user,admin,investigator)
    frontend=Path(__file__).resolve().parent.parent/"web/dist"
    if frontend.exists():app.mount("/",StaticFiles(directory=frontend,html=True),name="web")
    else:
        @app.get("/")
        def frontend_missing():return {"message":"Build the web UI with pnpm --dir web build. API documentation: /api/docs"}
    return app


