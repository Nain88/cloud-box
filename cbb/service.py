import base64
import io
import json
import os
import secrets
import shutil
import time
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from html import escape
import httpx
from sqlalchemy import select, update, delete, func, and_, or_
from . import db as D
from .config import Settings
from .crypto import uid, now, sha, file_sha, canon, dumps, loads, chain_hash, atomic_write, keypair, public_b64, sign, verify_signature
from .schema import WireEvent, normalize, parse_time


class DomainError(Exception):
    def __init__(self, code, message, status=400):
        self.code,self.message,self.status=code,message,status


def row(c, stmt):
    r=c.execute(stmt).mappings().first()
    return dict(r) if r else None
def rows(c, stmt): return [dict(x) for x in c.execute(stmt).mappings()]


class Service:
    def __init__(self, settings=None):
        self.settings=(settings or Settings()).prepare()
        self.db=D.Database(self.settings.database_url)
        self.root=self.settings.data
        self.key=None if self.settings.signer_url else keypair(self.root/"keys/signing.pem")
        with self.db.tx() as c:
            meta=row(c,select(D.config).where(D.config.c.id=="deployment"))
            if meta:
                self.deployment=loads(meta["value"])
                if self.key and public_b64(self.key)!=self.deployment["public_key"]:
                    raise ValueError("Signing key does not match deployment. Restore the original key; do not silently rotate.")
            else:
                pub=self._signer_public() if self.settings.signer_url else public_b64(self.key)
                self.deployment={"id":uid(),"public_key":pub,"created_at":now(),"version":"0.1.0"}
                c.execute(D.config.insert().values(id="deployment",value=dumps(self.deployment),version=1,updated_at=now()))
            for purpose in ("evidence","custody"):
                if not row(c,select(D.chains).where(D.chains.c.purpose==purpose)):
                    chain_id=uid(); gen=sha(b"CBB-GENESIS-v1\0"+canon({"deployment_id":self.deployment["id"],"chain_id":chain_id,"epoch":"1","purpose":purpose}))
                    c.execute(D.chains.insert().values(id=chain_id,purpose=purpose,genesis=gen,head_sequence=0,head_hash=gen))
        self.bootstrap_file=self.root/"keys/bootstrap.token"
        with self.db.read() as c: has_users=c.execute(select(func.count()).select_from(D.users)).scalar()
        if not has_users and not self.bootstrap_file.exists():
            atomic_write(self.bootstrap_file,secrets.token_urlsafe(32).encode())
            if os.name!="nt":self.bootstrap_file.chmod(0o600)

    def _signer_public(self):
        r=httpx.get(self.settings.signer_url+"/public-key",headers={"Authorization":"Bearer "+self.settings.signer_token},timeout=10)
        r.raise_for_status();return r.json()["public_key"]

    def signed(self, domain, payload):
        if self.key: return sign(self.key,domain,payload)
        r=httpx.post(self.settings.signer_url+"/sign",json={"domain":domain,"payload":payload},headers={"Authorization":"Bearer "+self.settings.signer_token},timeout=10)
        r.raise_for_status();doc=r.json();verify_signature(doc,domain,self.deployment["public_key"]);return doc

    def chain(self,c,purpose): return row(c,select(D.chains).where(D.chains.c.purpose==purpose))

    def audit(self,c,actor,action,target,result="SUCCESS",reason="",details=None):
        chain=self.chain(c,"custody");seq=chain["head_sequence"]+1
        envelope={"id":uid(),"actor":actor,"action":action,"target":target,"result":result,"reason":reason,"details":details or {},"at":now(),"sequence":str(seq)}
        encoded=canon(envelope);digest=chain_hash(chain["head_hash"],seq,encoded)
        c.execute(D.custody.insert().values(id=envelope["id"],sequence=seq,envelope=encoded,previous_hash=chain["head_hash"],entry_hash=digest,actor=actor,action=action,target=target,created_at=envelope["at"]))
        c.execute(update(D.chains).where(D.chains.c.id==chain["id"]).values(head_sequence=seq,head_hash=digest))

    def allowed_case(self,c,user,case_id,write=False):
        case=row(c,select(D.cases).where(D.cases.c.id==case_id))
        if not case:raise DomainError("NOT_FOUND","Case not found",404)
        member=row(c,select(D.case_members).where(and_(D.case_members.c.case_id==case_id,D.case_members.c.user_id==user["id"])))
        if case["owner_id"]!=user["id"] and not member:raise DomainError("NOT_FOUND","Case not found",404)
        if write and user["role"] not in ("investigator","admin"):raise DomainError("FORBIDDEN","Case editing requires investigator access",403)
        return case

    def visible_evidence(self,c,user,evidence_id):
        item=row(c,select(D.evidence).where(D.evidence.c.id==evidence_id))
        if not item:raise DomainError("NOT_FOUND","Evidence not found",404)
        if user["role"]=="investigator":return item
        memberships=rows(c,select(D.case_evidence.c.case_id).where(and_(D.case_evidence.c.evidence_id==evidence_id,D.case_evidence.c.active==True)))
        for member in memberships:
            try:self.allowed_case(c,user,member["case_id"]);return item
            except DomainError:pass
        raise DomainError("NOT_FOUND","Evidence not found in an assigned case",404)

    def scope_evidence(self,user):
        if user["role"]=="investigator":return None
        assigned=select(D.cases.c.id).where(or_(D.cases.c.owner_id==user["id"],D.cases.c.id.in_(select(D.case_members.c.case_id).where(D.case_members.c.user_id==user["id"]))))
        return D.evidence.c.id.in_(select(D.case_evidence.c.evidence_id).where(and_(D.case_evidence.c.case_id.in_(assigned),D.case_evidence.c.active==True)))

    def enroll(self,token,name=None):
        with self.db.tx() as c:
            e=row(c,select(D.enrollments).where(D.enrollments.c.token_hash==sha(token.encode())))
            if not e or e["used"] or e["expires"]<time.time():raise DomainError("INVALID_ENROLLMENT","Enrollment token expired or invalid",403)
            asset_id=uid();collector_id=uid();secret=secrets.token_urlsafe(40)
            c.execute(D.assets.insert().values(id=asset_id,name=name or e["name"],os=e["os"],criticality=3))
            c.execute(D.collectors.insert().values(id=collector_id,asset_id=asset_id,name=name or e["name"],token_hash=sha(secret.encode()),state="ACTIVE",created_at=now(),health="{}",configuration=dumps({"paths":[],"channels":["System"],"poll_seconds":5,"max_file_bytes":20971520}),config_version=1))
            c.execute(update(D.enrollments).where(D.enrollments.c.id==e["id"]).values(used=True))
            self.audit(c,collector_id,"COLLECTOR_ENROLLED",collector_id)
            return {"collector_id":collector_id,"asset_id":asset_id,"token":secret,"server_signing_key":self.deployment["public_key"]}

    def accept(self,collector,items):
        if not isinstance(items,list):raise DomainError("INVALID_BATCH","Events must be an array",422)
        if len(items)>500:raise DomainError("TOO_MANY_EVENTS","Maximum 500 events per batch",413)
        if shutil.disk_usage(self.root).free < 50*1024**2:raise DomainError("STORAGE_FULL","Insufficient durable storage",503)
        outcomes=[]
        for item in items:
            if not isinstance(item,dict):
                outcomes.append({"source_seq":"","outcome":"rejected","code":"INVALID_EVENT","detail":"Event must be an object","retryable":False});continue
            try:
                w=WireEvent.model_validate(item).model_dump()
                raw=base64.b64decode(w["raw_base64"],validate=True)
                if len(raw)>self.settings.max_event_bytes:raise ValueError("Event exceeds 64 KiB")
                if sha(raw)!=w["raw_sha256"]:raise ValueError("Raw digest mismatch")
                if parse_time(w["collected_at"]) is None:raise ValueError("Collection time requires a timezone")
                encoded=canon(w);payload_hash=sha(encoded)
                with self.db.tx() as c:
                    old=row(c,select(D.receipts).where(and_(D.receipts.c.collector_id==collector["id"],D.receipts.c.boot_id==w["boot_id"],D.receipts.c.source_seq==w["source_seq"])))
                    if old:
                        conflict=old["payload_hash"]!=payload_hash
                        if conflict:self.audit(c,collector["id"],"INGEST_CONFLICT",old["id"],"DENIED")
                        outcomes.append({"source_seq":w["source_seq"],"outcome":"conflict" if conflict else "duplicate","receipt_id":old["id"],"evidence_id":old["evidence_id"],"preservation_state":old["state"]})
                    else:
                        receipt_id,evidence_id=uid(),uid()
                        c.execute(D.receipts.insert().values(id=receipt_id,collector_id=collector["id"],boot_id=w["boot_id"],source_seq=w["source_seq"],payload_hash=payload_hash,payload=encoded.decode(),evidence_id=evidence_id,state="STAGED",received_at=now()))
                        outcomes.append({"source_seq":w["source_seq"],"outcome":"accepted","receipt_id":receipt_id,"evidence_id":evidence_id,"preservation_state":"STAGED"})
            except (ValueError,TypeError,KeyError) as ex:
                outcomes.append({"source_seq":str(item.get("source_seq","")),"outcome":"rejected","code":"INVALID_EVENT","detail":str(ex)[:300],"retryable":False})
        return outcomes

    def close_segments(self,c):
        for seg in rows(c,select(D.segments).where(D.segments.c.closed==False)):
            path=self.root/seg["path"]
            if path.exists():
                digest=sha(path.read_bytes())
                c.execute(update(D.segments).where(D.segments.c.id==seg["id"]).values(closed=True,sha256=digest,size=path.stat().st_size))
                entries=rows(c,select(D.evidence).where(D.evidence.c.segment_id==seg["id"]).order_by(D.evidence.c.sequence))
                manifest={"segment_id":seg["id"],"sha256":digest,"size":str(path.stat().st_size),"records":[{"id":r["id"],"sequence":str(r["sequence"]),"offset":str(r["raw_offset"]),"length":str(r["raw_length"]),"envelope":base64.b64encode(r["envelope"]).decode(),"record_hash":r["record_hash"],"previous_hash":r["previous_hash"]} for r in entries]}
                atomic_write(path.with_suffix(".manifest.json"),canon(manifest))

    def seal_pending(self,limit=100):
        with self.db.read() as c: pending=rows(c,select(D.receipts.c.id).where(D.receipts.c.state=="STAGED").order_by(D.receipts.c.received_at).limit(limit))
        for r in pending:
            try:
                with self.db.tx() as c:
                    receipt=row(c,select(D.receipts).where(D.receipts.c.id==r["id"]))
                    if receipt["state"]!="STAGED":continue
                    collector=row(c,select(D.collectors).where(D.collectors.c.id==receipt["collector_id"]))
                    wire=loads(receipt["payload"]);raw=base64.b64decode(wire["raw_base64"])
                    seg=row(c,select(D.segments).where(D.segments.c.closed==False))
                    if seg and seg["size"]>=self.settings.segment_bytes:self.close_segments(c);seg=None
                    if not seg:
                        seg={"id":uid(),"created_at":now()};seg["path"]="archive/"+seg["id"]+".jsonl"
                        c.execute(D.segments.insert().values(**seg,size=0,closed=False))
                    path=self.root/seg["path"]
                    wrapper=canon({"wrapper_version":1,"evidence_id":receipt["evidence_id"],"receipt_id":receipt["id"],"raw_base64":wire["raw_base64"],"raw_sha256":sha(raw),"raw_media_type":wire["raw_media_type"]})+b"\n"
                    with path.open("ab") as f:
                        offset=f.tell();f.write(wrapper);f.flush();os.fsync(f.fileno())
                    raw_ref={"segment_id":seg["id"],"offset":str(offset),"length":str(len(wrapper)),"sha256":sha(raw),"media_type":wire["raw_media_type"]}
                    env=normalize(wire,collector,receipt["evidence_id"],receipt["received_at"],raw_ref)
                    encoded=canon(env)
                    if len(encoded)>65536:raise ValueError("Normalized envelope exceeds limit")
                    chain=self.chain(c,"evidence");seq=chain["head_sequence"]+1;digest=chain_hash(chain["head_hash"],seq,encoded)
                    c.execute(D.evidence.insert().values(id=receipt["evidence_id"],chain_id=chain["id"],sequence=seq,collector_id=collector["id"],asset_id=collector["asset_id"],segment_id=seg["id"],raw_offset=offset,raw_length=len(wrapper),raw_sha256=sha(raw),envelope=encoded,envelope_sha256=sha(encoded),previous_hash=chain["head_hash"],record_hash=digest,source_type=env["source_type"],event_type=env["event_type"],occurred_at=env["occurred_at"],received_at=receipt["received_at"],severity=env["severity"],summary=env["summary"]))
                    c.execute(update(D.segments).where(D.segments.c.id==seg["id"]).values(size=offset+len(wrapper)))
                    c.execute(update(D.chains).where(D.chains.c.id==chain["id"]).values(head_sequence=seq,head_hash=digest))
                    c.execute(update(D.receipts).where(D.receipts.c.id==receipt["id"]).values(state="SEALED"))
                    self.audit(c,collector["id"],"EVIDENCE_SEALED",receipt["evidence_id"],details={"sequence":str(seq)})
                    # Publish sensor indicators in the sealing transaction so a
                    # queue of historical correlation jobs cannot hide a fresh match.
                    if env['source_type'] in {'suricata.eve','windows.firewall'}:
                        item=row(c,select(D.evidence).where(D.evidence.c.id==receipt['evidence_id']))
                        if env['event_type']=='network.alert':self.record_indicator(c,item)
                        elif env['event_type']=='firewall.drop':
                            from .detection import firewall_burst
                            firewall_burst(self,c,item,env)
                    intake=loads(collector['configuration']).get('intake_case_id')
                    if intake:
                        case=row(c,select(D.cases).where(D.cases.c.id==intake))
                        if case and case['status'] not in {'CLOSED','ARCHIVED'}:
                            version=case['version']+1
                            c.execute(update(D.cases).where(D.cases.c.id==intake).values(version=version,updated_at=now()))
                            c.execute(D.case_evidence.insert().values(id=uid(),case_id=intake,evidence_id=receipt['evidence_id'],case_version=version,active=True,reason='Configured live collector intake',created_at=now()))
                            self.audit(c,collector['id'],'CASE_INTAKE',intake,details={'evidence_id':receipt['evidence_id'],'case_version':version})
                    self.create_job(c,"analyze",collector["id"],{"evidence_id":receipt["evidence_id"]},operation_key="analyze:"+receipt["evidence_id"])
            except (ValueError,KeyError,UnicodeError) as ex:
                with self.db.tx() as c:
                    c.execute(update(D.receipts).where(D.receipts.c.id==r["id"]).values(state="QUARANTINED",error=str(ex)[:500]))
                    self.audit(c,"system","QUARANTINE",r["id"],"ERROR",details={"error":str(ex)[:200]})
        return len(pending)

    def read_raw(self,c,item):
        seg=row(c,select(D.segments).where(D.segments.c.id==item["segment_id"]))
        with (self.root/seg["path"]).open("rb") as f:
            f.seek(item["raw_offset"]);wrapper=loads(f.read(item["raw_length"]))
        if wrapper["evidence_id"]!=item["id"]:raise ValueError("Raw wrapper identity mismatch")
        return base64.b64decode(wrapper["raw_base64"],validate=True)

    def checkpoint(self,actor="system"):
        with self.db.tx() as c:
            self.close_segments(c)
            previous=row(c,select(D.checkpoints).order_by(D.checkpoints.c.sequence.desc()).limit(1))
            heads=rows(c,select(D.chains))
            segs=rows(c,select(D.segments).where(D.segments.c.closed==True))
            payload={"checkpoint_version":"1.0","checkpoint_id":uid(),"checkpoint_seq":str(previous["sequence"]+1 if previous else 1),"deployment_id":self.deployment["id"],"created_at":now(),"previous_checkpoint_sha256":previous["sha256"] if previous else "0"*64,"chains":[{"id":h["id"],"purpose":h["purpose"],"sequence":str(h["head_sequence"]),"head_hash":h["head_hash"],"genesis":h["genesis"]} for h in heads],"segments":[{"id":s["id"],"sha256":s["sha256"],"manifest_sha256":sha((self.root/s["path"]).with_suffix(".manifest.json").read_bytes())} for s in segs if (self.root/s["path"]).with_suffix(".manifest.json").exists()]}
            document=self.signed("CBB-CHECKPOINT-v1",payload)
            verify_signature(document,"CBB-CHECKPOINT-v1",self.deployment["public_key"])
            encoded=canon(document);digest=sha(encoded)
            atomic_write(self.root/"checkpoints"/(payload["checkpoint_id"]+".json"),encoded)
            c.execute(D.checkpoints.insert().values(id=payload["checkpoint_id"],sequence=int(payload["checkpoint_seq"]),document=encoded.decode(),sha256=digest,created_at=payload["created_at"]))
            self.audit(c,actor,"CHECKPOINT_CREATED",payload["checkpoint_id"],details={"sha256":digest})
        return document

    def anchor_pending(self):
        if not self.settings.witness_url or not self.settings.witness_public_key:return
        with self.db.read() as c:
            pending=rows(c,select(D.checkpoints).where(~D.checkpoints.c.id.in_(select(D.witness_receipts.c.checkpoint_id))).order_by(D.checkpoints.c.sequence))
        for cp in pending:
            resp=httpx.post(self.settings.witness_url+"/checkpoints",json=loads(cp["document"]),timeout=15);resp.raise_for_status()
            receipt=resp.json();data=verify_signature(receipt,"CBB-WITNESS-v1",self.settings.witness_public_key)
            if data["checkpoint_sha256"]!=cp["sha256"]:raise ValueError("Witness digest mismatch")
            with self.db.tx() as c:
                if not row(c,select(D.witness_receipts).where(D.witness_receipts.c.checkpoint_id==cp["id"])):
                    c.execute(D.witness_receipts.insert().values(id=uid(),checkpoint_id=cp["id"],receipt=dumps(receipt),independent=self.settings.witness_independent,created_at=now()))
                    self.audit(c,"system","CHECKPOINT_WITNESSED",cp["id"])

    def verify(self,checkpoint_doc=None):
        failures=[];checked=0;unavailable=0
        with self.db.read() as c:
            latest=row(c,select(D.checkpoints).order_by(D.checkpoints.c.sequence.desc()).limit(1))
            cp=checkpoint_doc or (loads(latest["document"]) if latest else None)
            trusted=None
            if cp:
                try:trusted=verify_signature(cp,"CBB-CHECKPOINT-v1",self.deployment["public_key"])
                except Exception:failures.append({"code":"BAD_SIGNATURE","target":"checkpoint"})
            previous_cp="0"*64
            for cp_index, saved in enumerate(rows(c,select(D.checkpoints).order_by(D.checkpoints.c.sequence)),1):
                try:
                    doc=loads(saved["document"]);value=verify_signature(doc,"CBB-CHECKPOINT-v1",self.deployment["public_key"])
                    if saved["sequence"]!=cp_index or int(value["checkpoint_seq"])!=cp_index or value["previous_checkpoint_sha256"]!=previous_cp or value["deployment_id"]!=self.deployment["id"] or sha(canon(doc))!=saved["sha256"]:
                        failures.append({"code":"CHECKPOINT_CONTINUITY","target":saved["id"]})
                    previous_cp=saved["sha256"]
                except Exception:failures.append({"code":"BAD_SIGNATURE","target":saved["id"]})
            if trusted and trusted.get("deployment_id")!=self.deployment["id"]:
                failures.append({"code":"DEPLOYMENT_MISMATCH","target":"checkpoint"})
            for purpose,table,hash_col in (("evidence",D.evidence,"record_hash"),("custody",D.custody,"entry_hash")):
                chain=self.chain(c,purpose);previous=chain["genesis"];expected=1;heads={0:previous}
                for item in rows(c,select(table).order_by(table.c.sequence)):
                    if item["sequence"]!=expected:failures.append({"code":"MISSING_RECORD","target":purpose,"sequence":expected})
                    if item["previous_hash"]!=previous:failures.append({"code":"BROKEN_LINK","target":item["id"]})
                    digest=chain_hash(previous,item["sequence"],item["envelope"])
                    if digest!=item[hash_col]:failures.append({"code":"ENVELOPE_MODIFIED","target":item["id"]})
                    try:
                        if canon(loads(item["envelope"]))!=item["envelope"]:failures.append({"code":"NON_CANONICAL","target":item["id"]})
                    except Exception:failures.append({"code":"INVALID_ENVELOPE","target":item["id"]})
                    if purpose=="evidence":
                        checked+=1
                        try:
                            raw=self.read_raw(c,item)
                            env=loads(item["envelope"])
                            if sha(raw)!=item["raw_sha256"] or sha(raw)!=env["raw"]["sha256"]:failures.append({"code":"RAW_HASH_MISMATCH","target":item["id"]})
                            expected_ref={"segment_id":item["segment_id"],"offset":str(item["raw_offset"]),"length":str(item["raw_length"]),"sha256":item["raw_sha256"]}
                            projections=("collector_id","asset_id","source_type","event_type","occurred_at","received_at","severity","summary")
                            if any(env["raw"].get(k)!=v for k,v in expected_ref.items()) or env.get("evidence_id")!=item["id"] or any(env.get(k)!=item[k] for k in projections) or sha(item["envelope"])!=item["envelope_sha256"]:
                                failures.append({"code":"PROJECTION_MISMATCH","target":item["id"]})
                        except (OSError,ValueError,KeyError):unavailable+=1;failures.append({"code":"RAW_UNAVAILABLE","target":item["id"]})
                    previous=digest;heads[item["sequence"]]=digest;expected=item["sequence"]+1
                if chain["head_sequence"]!=expected-1 or chain["head_hash"]!=previous:failures.append({"code":"HEAD_MISMATCH","target":purpose})
                if trusted:
                    anchor=next((h for h in trusted["chains"] if h["purpose"]==purpose),None)
                    if not anchor or anchor["id"]!=chain["id"] or anchor.get("genesis")!=chain["genesis"] or heads.get(int(anchor["sequence"]))!=anchor["head_hash"]:failures.append({"code":"CHECKPOINT_MISMATCH","target":purpose})
            for seg in rows(c,select(D.segments).where(D.segments.c.closed==True)):
                try:
                    if sha((self.root/seg["path"]).read_bytes())!=seg["sha256"]:failures.append({"code":"SEGMENT_MISMATCH","target":seg["id"]})
                except OSError:failures.append({"code":"SEGMENT_UNAVAILABLE","target":seg["id"]})
            if trusted:
                for seg in trusted.get("segments",[]):
                    actual=row(c,select(D.segments).where(D.segments.c.id==seg["id"]))
                    if not actual or actual["sha256"]!=seg["sha256"]:failures.append({"code":"SEGMENT_CHECKPOINT_MISMATCH","target":seg["id"]})
                    if actual:
                        try:
                            manifest=(self.root/actual["path"]).with_suffix(".manifest.json").read_bytes()
                            if sha(manifest)!=seg["manifest_sha256"]:failures.append({"code":"MANIFEST_MODIFIED","target":seg["id"]})
                        except OSError:failures.append({"code":"MANIFEST_UNAVAILABLE","target":seg["id"]})
            for artifact in rows(c,select(D.artifacts)):
                try:
                    import hashlib
                    digest=hashlib.sha256()
                    with (self.root/artifact["path"]).open("rb") as f:
                        for chunk in iter(lambda:f.read(1024*1024),b""):digest.update(chunk)
                    evidence=row(c,select(D.evidence).where(D.evidence.c.id==artifact["evidence_id"]))
                    original=loads(self.read_raw(c,evidence)) if evidence else {}
                    if digest.hexdigest()!=artifact["sha256"] or original.get("sha256")!=artifact["sha256"] or (self.root/artifact["path"]).stat().st_size!=artifact["size"]:failures.append({"code":"ARTIFACT_MODIFIED","target":artifact["id"]})
                except (OSError,ValueError,KeyError,TypeError):failures.append({"code":"ARTIFACT_UNAVAILABLE","target":artifact["id"]})
            anchored=False
            if trusted:
                receipt=row(c,select(D.witness_receipts).where(D.witness_receipts.c.checkpoint_id==trusted["checkpoint_id"]))
                if receipt and receipt["independent"]:
                    try:
                        r=verify_signature(loads(receipt["receipt"]),"CBB-WITNESS-v1",self.settings.witness_public_key)
                        anchored=r["checkpoint_sha256"]==sha(canon(cp))
                    except Exception:failures.append({"code":"BAD_WITNESS_RECEIPT","target":trusted["checkpoint_id"]})
        return {"status":"INVALID" if failures else ("VALID" if trusted else "UNANCHORED"),"assurance":"EXTERNALLY_ANCHORED" if anchored else "LOCAL_CHECK_ONLY","checked":checked,"unavailable":unavailable,"failures":failures,"checkpoint_id":trusted["checkpoint_id"] if trusted else None,"verified_at":now(),"verifier_version":"1.0.0"}

    def create_job(self,c,kind,actor,payload,case_id=None,operation_key=None):
        key=operation_key or uid()
        old=row(c,select(D.jobs).where(D.jobs.c.operation_key==key))
        if old:
            if old["payload"]!=dumps(payload):raise DomainError("IDEMPOTENCY_CONFLICT","Key reused with different input",409)
            return old["id"]
        jid=uid();c.execute(D.jobs.insert().values(id=jid,kind=kind,state="QUEUED",actor_id=actor,case_id=case_id,payload=dumps(payload),operation_key=key,progress=0,attempts=0,next_attempt=0,created_at=now(),updated_at=now()))
        return jid

    def record_indicator(self,c,item):
        event_type=item['event_type']
        if item['severity']<3 and event_type not in {'log.clear','registry.change','auth.failure','yara.match','network.alert'}:return
        key='rule-v1:'+item['id']
        if row(c,select(D.alerts.c.id).where(D.alerts.c.dedup_key==key)):return
        c.execute(D.alerts.insert().values(id=uid(),evidence_id=item['id'],asset_id=item['asset_id'],rule_id='rules-v1/'+event_type,severity=item['severity'],risk=item['severity']*20,explanation=f"{item['summary']} ({event_type}). Inspect original evidence and source context.",status='NEW',components=dumps({'severity':item['severity']/5,'model':'not_scored'}),created_at=now(),dedup_key=key))

    def analyze(self,evidence_id):
        with self.db.tx() as c:
            item=row(c,select(D.evidence).where(D.evidence.c.id==evidence_id));env=loads(item["envelope"])
            etype=item["event_type"]
            from .detection import firewall_burst
            firewall_burst(self,c,item,env)
            self.record_indicator(c,item)
            if etype.startswith(("file.","fim.","network.")) and item["occurred_at"]:
                current=datetime.fromisoformat(item["occurred_at"].replace("Z","+00:00"))
                candidates=rows(c,select(D.evidence).where(and_(D.evidence.c.asset_id==item["asset_id"],D.evidence.c.event_type=="process.create")).order_by(D.evidence.c.sequence.desc()).limit(200))
                for prev in candidates:
                    if not prev["occurred_at"]:continue
                    delta=(current-datetime.fromisoformat(prev["occurred_at"].replace("Z","+00:00"))).total_seconds()
                    if 0<=delta<=(60 if etype.startswith("network.") else 30):
                        subject=loads(prev["envelope"])["subject"];same=bool(subject.get("process_guid") and subject.get("process_guid")==env["subject"].get("process_guid"))
                        key="C01:"+prev["id"]+":"+evidence_id
                        if not row(c,select(D.incidents).where(D.incidents.c.dedup_key==key)):
                            c.execute(D.incidents.insert().values(id=uid(),asset_id=item["asset_id"],title="Process followed by "+etype,confidence=.9 if same else .45,rule_id="C01/1.0",version=1,evidence_ids=dumps([prev["id"],evidence_id]),decisions="[]",created_at=now(),dedup_key=key))
                        break

    def make_export(self,case_id,actor_id,evidence_ids,case_version,case_snapshot=None,notes_snapshot=None,ai_snapshot=None,job_id=None):
        def progress(value):
            if job_id:
                with self.db.tx() as c:c.execute(update(D.jobs).where(D.jobs.c.id==job_id).values(progress=value,updated_at=now()))
        progress(5)
        cp=self.checkpoint(actor_id);progress(10);verification=self.verify(cp);progress(30)
        if verification["status"]=="INVALID":raise ValueError("Export blocked: archive verification failed")
        package_id=uid();path=self.root/"exports"/(package_id+".zip")
        entries=[];files={}
        with self.db.read() as c:
            case=case_snapshot or row(c,select(D.cases).where(D.cases.c.id==case_id))
            for index,eid in enumerate(evidence_ids):
                if index and index%500==0:progress(30+int(40*index/len(evidence_ids)))
                item=row(c,select(D.evidence).where(D.evidence.c.id==eid))
                if not item:raise ValueError("Selected evidence no longer available")
                raw=self.read_raw(c,item)
                if sha(raw)!=item["raw_sha256"]:raise ValueError("Export blocked: raw digest mismatch")
                files["evidence/"+eid+".raw"]=raw;files["evidence/"+eid+".json"]=item["envelope"]
                entries.append({"id":eid,"sequence":str(item["sequence"]),"raw_path":"evidence/"+eid+".raw","envelope_path":"evidence/"+eid+".json","record_hash":item["record_hash"],"raw_sha256":item["raw_sha256"],"source_type":item["source_type"],"event_type":item["event_type"],"occurred_at":item["occurred_at"],"received_at":item["received_at"],"summary":item["summary"]})
                for artifact in rows(c,select(D.artifacts).where(D.artifacts.c.evidence_id==eid)):
                    files["artifacts/"+artifact["id"]+".bin"]=self.root/artifact["path"]
            head=int(next(h for h in cp["payload"]["chains"] if h["purpose"]=="evidence")["sequence"])
            proofs=rows(c,select(D.evidence.c.sequence,D.evidence.c.envelope_sha256,D.evidence.c.previous_hash,D.evidence.c.record_hash).where(D.evidence.c.sequence<=head).order_by(D.evidence.c.sequence))
            for p in proofs:p["sequence"]=str(p["sequence"])
            note_list=notes_snapshot if notes_snapshot is not None else rows(c,select(D.notes).where(D.notes.c.case_id==case_id).order_by(D.notes.c.created_at))
            targets=list(dict.fromkeys([case_id,*evidence_ids]))
            custody=[]
            for offset in range(0,len(targets),500):
                custody.extend(rows(c,select(D.custody).where(D.custody.c.target.in_(targets[offset:offset+500]))))
            custody.sort(key=lambda r:r['sequence'])
            custody=[{**r,"envelope":loads(r["envelope"])} for r in custody]
            ai=ai_snapshot or []
        files["proof.json"]=canon(proofs);files["checkpoint.json"]=canon(cp);files["verification.json"]=canon(verification)
        files["notes.json"]=canon(note_list)
        files["case.json"]=canon(case);files["custody.json"]=canon(custody);files["ai-assistance.json"]=canon(ai)
        progress(75)
        from .reporting import reports
        files["report.docx"],files["report.pdf"]=reports(case,case_version,entries,note_list,verification,custody,ai)
        report=f"<!doctype html><meta charset='utf-8'><title>Cyber Black Box case report</title><style>body{{font:16px system-ui;max-width:900px;margin:4rem auto;line-height:1.6}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px}}</style><h1>{escape(case['title'])}</h1><p>Case {escape(case_id)} · Snapshot version {case_version}</p><p>{escape(case['description'] or '')}</p><h2>Analyst conclusion</h2><p>{escape(case['conclusion'] or 'No conclusion recorded.')}</p><h2>Evidence</h2><ul>"+"".join(f"<li>{escape(e['id'])} — sequence {e['sequence']}</li>" for e in entries)+f"</ul><h2>Integrity</h2><p>{escape(verification['status'])} · {escape(verification['assurance'])}</p><p>This report concerns selected captured observations. It does not establish completeness, source truth, attack attribution or legal admissibility.</p>"
        files["report.html"]=report.encode()
        files["README.txt"]=b"Verify with: cbb verify-package case.zip --public-key <separately trusted base64 key>\nThe key inside a package must not be trusted solely because it arrived with that package. report.html is the readable report.\n"
        manifest={"package_id":package_id,"case_id":case_id,"case_version":case_version,"generated_at":now(),"evidence":entries,"files":[{"path":name,"size":str(data.stat().st_size if isinstance(data,Path) else len(data)),"sha256":file_sha(data) if isinstance(data,Path) else sha(data)} for name,data in files.items()]}
        files["manifest.json"]=canon(manifest);files["manifest.signature.json"]=canon(self.signed("CBB-EXPORT-v1",manifest))
        progress(90)
        with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
            for name,data in files.items():
                if isinstance(data,Path):z.write(data,name)
                else:z.writestr(name,data)
        digest=file_sha(path)
        with self.db.tx() as c:
            c.execute(D.exports.insert().values(id=package_id,case_id=case_id,case_version=case_version,path=str(path.relative_to(self.root)),sha256=digest,manifest=dumps(manifest),created_at=now()))
            self.audit(c,actor_id,"EXPORT_CREATED",package_id,details={"case_id":case_id,"sha256":digest})
        return {"export_id":package_id,"sha256":digest,"verification":verification}

    def replicate(self):
        if not self.settings.s3_bucket:return {"status":"NOT_CONFIGURED"}
        import boto3
        from datetime import timedelta
        client=boto3.client("s3",endpoint_url=self.settings.s3_endpoint or None)
        count=0
        with self.db.read() as c:todo=rows(c,select(D.segments).where(and_(D.segments.c.closed==True,D.segments.c.remote==None)))
        for seg in todo:
            path=self.root/seg["path"];raw=path.read_bytes()
            if sha(raw)!=seg["sha256"]:raise ValueError("Local segment hash failed before replication")
            result=client.put_object(Bucket=self.settings.s3_bucket,Key=seg["path"],Body=raw,ChecksumSHA256=base64.b64encode(bytes.fromhex(seg["sha256"])).decode(),ObjectLockMode=self.settings.s3_retention_mode,ObjectLockRetainUntilDate=datetime.now(timezone.utc)+timedelta(days=self.settings.s3_retention_days))
            version=result.get("VersionId")
            if not version:raise ValueError("Archive bucket must have versioning enabled")
            downloaded=client.get_object(Bucket=self.settings.s3_bucket,Key=seg["path"],VersionId=version)["Body"].read()
            if sha(downloaded)!=seg["sha256"]:raise ValueError("Remote verification failed")
            manifest=path.with_suffix(".manifest.json").read_bytes()
            mr=client.put_object(Bucket=self.settings.s3_bucket,Key=seg["path"]+".manifest.json",Body=manifest,ObjectLockMode=self.settings.s3_retention_mode,ObjectLockRetainUntilDate=datetime.now(timezone.utc)+timedelta(days=self.settings.s3_retention_days))
            with self.db.tx() as c:
                c.execute(update(D.segments).where(D.segments.c.id==seg["id"]).values(remote=dumps({"bucket":self.settings.s3_bucket,"version_id":version,"manifest_version_id":mr.get("VersionId"),"verified_at":now()})))
                self.audit(c,"system","ARCHIVE_REPLICATED",seg["id"])
            count+=1
        return {"replicated":count}

    def run_job(self,job):
        payload=loads(job["payload"])
        if job["kind"]=="analyze":self.analyze(payload["evidence_id"]);return {"analyzed":payload["evidence_id"]}
        if job["kind"]=="verify":
            result=self.verify(payload.get("checkpoint"))
            with self.db.tx() as c:
                c.execute(D.verifications.insert().values(id=uid(),job_id=job["id"],result=dumps(result),created_at=now()))
                self.audit(c,job["actor_id"],"VERIFICATION_COMPLETED",job["id"],result["status"])
            return result
        if job["kind"]=="export":return self.make_export(job["case_id"],job["actor_id"],payload["evidence_ids"],payload["case_version"],payload.get("case_snapshot"),payload.get("notes_snapshot"),payload.get("ai_snapshot"),job_id=job["id"])
        if job["kind"]=="mega-backup":
            from .cloud import replicate_mega
            return replicate_mega(self,payload)
        if job["kind"]=="mega-restore-check":
            from .cloud import restore_check
            return restore_check(self,payload)
        if job["kind"]=="ai-assist":
            from .assistant import analyze_case
            return analyze_case(self,payload)
        if job["kind"]=="train":
            from .analytics import train
            return train(self,payload)
        if job["kind"]=="score":
            from .analytics import score
            return score(self,payload)
        if job["kind"]=="replicate":return self.replicate()
        if job["kind"]=="pcap":
            from .integrations import process_pcap
            return process_pcap(self,payload)
        raise ValueError("Unknown job type")

    def tick(self,background=False):
        if background:
            self._run_next_job(True)
            return
        self.seal_pending()
        deadline=time.monotonic()+1.0
        for _ in range(50):
            if time.monotonic()>=deadline or not self._run_next_job(False):break

    def _run_next_job(self,background):
        with self.db.tx() as c:
            kind_filter=D.jobs.c.kind!="analyze" if background else D.jobs.c.kind=="analyze"
            job=row(c,select(D.jobs).where(and_(D.jobs.c.state=="QUEUED",D.jobs.c.next_attempt<=time.time(),kind_filter)).order_by(D.jobs.c.created_at).limit(1))
            if job:c.execute(update(D.jobs).where(D.jobs.c.id==job["id"]).values(state="RUNNING",error=None,progress=0,attempts=job["attempts"]+1,updated_at=now()))
        if job:
            try:
                result=self.run_job(job)
                with self.db.tx() as c:c.execute(update(D.jobs).where(D.jobs.c.id==job["id"]).values(state="COMPLETE",progress=100,result=dumps(result),updated_at=now(),error=None))
            except Exception as ex:
                with self.db.tx() as c:
                    attempts=job["attempts"]+1
                    c.execute(update(D.jobs).where(D.jobs.c.id==job["id"]).values(state="FAILED" if attempts>=3 else "QUEUED",next_attempt=time.time()+min(600,5**attempts),error=type(ex).__name__+": "+str(ex)[:400],updated_at=now()))
        return job is not None
    def maintenance(self):
        """Periodic anchoring is independent of slow transfer/model jobs."""
        with self.db.read() as c:latest=row(c,select(D.checkpoints).order_by(D.checkpoints.c.sequence.desc()).limit(1))
        if not latest or time.time()-datetime.fromisoformat(latest["created_at"].replace("Z","+00:00")).timestamp()>=self.settings.checkpoint_seconds:
            self.checkpoint()
        self.anchor_pending()
        from .cloud import settings as mega_settings
        policy=mega_settings(self)
        if policy["enabled"] and policy["automatic"]:
            with self.db.tx() as c:
                latest_backup=row(c,select(D.jobs).where(D.jobs.c.kind=="mega-backup").order_by(D.jobs.c.created_at.desc()).limit(1))
                if not latest_backup or (latest_backup["state"] in {"COMPLETE","FAILED"} and time.time()-datetime.fromisoformat(latest_backup["created_at"].replace("Z","+00:00")).timestamp()>policy["interval_minutes"]*60):self.create_job(c,"mega-backup","system",{"actor_id":"system"})

    def recover_jobs(self):
        with self.db.tx() as c:
            c.execute(update(D.jobs).where(D.jobs.c.state=="RUNNING").values(state="QUEUED",error="Worker restarted; idempotent task rescheduled"))
            c.execute(update(D.acquisitions).where(D.acquisitions.c.state.in_(["LEASED","RUNNING"])).values(state="NEEDS_REVIEW",updated_at=now()))

