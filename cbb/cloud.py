"""One-way, hash-verified MEGA archival. Never mirrors local deletions."""
import os
import re
import tempfile
from pathlib import Path
from sqlalchemy import select, and_, update
from . import db as D
from .crypto import now,uid,file_sha,canon,sha,loads,dumps,atomic_write
from .service import DomainError,row,rows
from .tooling import mega_command

DEFAULTS={"enabled":False,"automatic":False,"interval_minutes":15,"remote_root":"/CyberBlackBox"}

def restore_check(service,payload):
    """Download to a new staging folder; never replace preserved originals."""
    with service.db.read() as c:obj=row(c,select(D.cloud_objects).where(D.cloud_objects.c.id==payload["object_id"]))
    if not obj:raise DomainError("NOT_FOUND","Backup object not found",404)
    if obj["size"]>__import__('shutil').disk_usage(service.root).free-50*1024**2:raise DomainError("VERIFY_CAPACITY","Insufficient free space for restore verification",503)
    target=service.root/"restore-staging"/uid();target.mkdir(parents=True)
    mega_command("get",obj["remote_path"],str(target)+os.sep)
    downloaded=target/Path(obj["local_path"]).name
    matched=downloaded.is_file() and file_sha(downloaded)==obj["sha256"]
    with service.db.tx() as c:
        c.execute(update(D.cloud_objects).where(D.cloud_objects.c.id==obj["id"]).values(state="VERIFIED" if matched else "MISMATCH",verified_at=now()))
        service.audit(c,payload["actor_id"],"MEGA_RESTORE_CHECK",obj["source_id"],result="SUCCESS" if matched else "FAILED",details={"object_id":obj["id"],"expected_sha256":obj["sha256"],"staging_path":str(target.relative_to(service.root))})
    if not matched:raise DomainError("REMOTE_HASH_MISMATCH","Restore bytes do not match preserved digest; staged output is untrusted",409)
    return {"verified":True,"sha256":obj["sha256"],"staging_path":str(downloaded.relative_to(service.root)),"originals_replaced":False}

def settings(service):
    with service.db.read() as c:r=row(c,select(D.config).where(D.config.c.id=="mega-policy"))
    return {**DEFAULTS,**(loads(r["value"]) if r else {})}

def candidates(service):
    result=[]
    with service.db.read() as c:
        for s in rows(c,select(D.segments).where(D.segments.c.closed==True)):
            result.extend([("segment",s["id"],s["path"],s["sha256"]),("manifest",s["id"],str(Path(s["path"]).with_suffix(".manifest.json")).replace("\\","/"),None)])
        for a in rows(c,select(D.artifacts)):result.append(("artifact",a["id"],a["path"],a["sha256"]))
        for a in rows(c,select(D.exports)):result.append(("report-package",a["id"],a["path"],a["sha256"]))
        for a in rows(c,select(D.checkpoints)):result.append(("checkpoint",a["id"],"checkpoints/"+a["id"]+".json",a["sha256"]))
    return result

def replicate_mega(service,payload):
    policy=settings(service)
    if not policy["enabled"]:raise DomainError("MEGA_DISABLED","Enable MEGA backup after signing in to official MEGAcmd",422)
    remote=policy["remote_root"]
    if not re.fullmatch(r"/[A-Za-z0-9_/-]{1,180}",remote) or ".." in remote:raise DomainError("MEGA_PATH","Use an absolute MEGA folder containing letters, digits, slash, dash or underscore",422)
    mega_command("whoami",timeout=15)
    service.checkpoint(payload.get("actor_id","system"))
    verification=service.verify()
    if verification["status"]=="INVALID":raise DomainError("INTEGRITY_FAILED","Cloud upload blocked because archive verification failed",409)
    prefix=remote.rstrip("/")+"/"+service.deployment["id"]
    count=0;already=0
    items=candidates(service)
    # Freeze custody and descriptive metadata without copying live database or secrets.
    with service.db.read() as c:
        custody=[{"sequence":str(r["sequence"]),"envelope":loads(r["envelope"]),"entry_hash":r["entry_hash"],"previous_hash":r["previous_hash"]} for r in rows(c,select(D.custody).order_by(D.custody.c.sequence))]
        metadata={"schema":"cbb.archive-metadata/1","deployment":service.deployment,"cases":rows(c,select(D.cases)),"case_members":rows(c,select(D.case_members)),"case_evidence":rows(c,select(D.case_evidence)),"notes":rows(c,select(D.notes)),"custody":custody,"witness_receipts":rows(c,select(D.witness_receipts)),"ai_runs":rows(c,select(D.ai_runs)),"assets":rows(c,select(D.assets)),"created_at":now()}
    snapshot_id=uid();snapshot=service.root/"cloud-snapshots"/(snapshot_id+".json")
    atomic_write(snapshot,canon(metadata));items.append(("metadata-snapshot",snapshot_id,str(snapshot.relative_to(service.root)).replace("\\","/"),file_sha(snapshot)))
    for kind,source_id,relative,expected in items:
        path=(service.root/relative).resolve()
        if not path.is_relative_to(service.root.resolve()) or not path.is_file():raise DomainError("ARCHIVE_PATH","Archive object is unavailable",409)
        digest=file_sha(path)
        if expected and digest!=expected:raise DomainError("OBJECT_MODIFIED","Object changed before cloud backup",409)
        with service.db.read() as c:old=row(c,select(D.cloud_objects).where(and_(D.cloud_objects.c.provider=="mega",D.cloud_objects.c.local_path==relative,D.cloud_objects.c.sha256==digest)))
        if old and old["state"]=="VERIFIED":already+=1;continue
        # Content-addressed remote names do not overwrite a prior different version.
        folder=prefix+"/objects/"+digest
        destination=folder+"/"+path.name
        mega_command("mkdir","-p",folder)
        mega_command("put",str(path),folder+"/")
        if file_sha(path)!=digest:raise DomainError("UPLOAD_RACE","Local object changed while uploading; no verified backup recorded",409)
        if path.stat().st_size>__import__('shutil').disk_usage(service.root).free-50*1024**2:raise DomainError("VERIFY_CAPACITY","Need free local space to read back and verify the remote object",503)
        with tempfile.TemporaryDirectory(prefix="mega-readback-",dir=service.root) as temp:
            mega_command("get",destination,temp+os.sep)
            downloaded=Path(temp)/path.name
            if not downloaded.is_file() or file_sha(downloaded)!=digest:raise DomainError("REMOTE_HASH_MISMATCH","MEGA readback did not match local evidence",409)
        with service.db.tx() as c:
            values={"provider":"mega","source_kind":kind,"source_id":source_id,"local_path":relative,"remote_path":destination,"sha256":digest,"size":path.stat().st_size,"state":"VERIFIED","verified_at":now()}
            if old:c.execute(update(D.cloud_objects).where(D.cloud_objects.c.id==old["id"]).values(**values))
            else:c.execute(D.cloud_objects.insert().values(id=uid(),created_at=now(),**values))
            service.audit(c,payload.get("actor_id","system"),"MEGA_OBJECT_VERIFIED",source_id,details={"kind":kind,"sha256":digest,"remote_path":destination})
        count+=1
    with service.db.read() as c:inventory=rows(c,select(D.cloud_objects).where(D.cloud_objects.c.provider=="mega"))
    manifest={"schema":"cbb.cloud-inventory/1","deployment_id":service.deployment["id"],"snapshot_id":snapshot_id,"created_at":now(),"objects":inventory,"protection":"Verified backup; not WORM or an independent witness","excludes":["private signing keys","user credentials","collector credentials","live database"]}
    signed=service.signed("CBB-EXPORT-v1",manifest)
    manifest_path=service.root/"cloud-snapshots"/(snapshot_id+".inventory.json");atomic_write(manifest_path,canon(signed))
    mega_command("mkdir","-p",prefix+"/inventories")
    mega_command("put",str(manifest_path),prefix+"/inventories/")
    with tempfile.TemporaryDirectory(prefix="mega-inventory-",dir=service.root) as temp:
        mega_command("get",prefix+"/inventories/"+manifest_path.name,temp+os.sep)
        if file_sha(Path(temp)/manifest_path.name)!=file_sha(manifest_path):raise DomainError("INVENTORY_MISMATCH","Cloud inventory readback failed",409)
    return {"uploaded_and_verified":count,"previously_verified":already,"inventory_remote_path":prefix+"/inventories/"+manifest_path.name,"protection":"VERIFIED_BACKUP_NOT_WORM","includes":"closed segments, manifests, artifacts, reports, checkpoints and metadata/custody snapshot","database_restore":"Use separate consistent database/key backup for full application recovery"}
