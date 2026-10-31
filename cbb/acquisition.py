"""Approved, signed acquisition plans and bounded resumable artifact transfer.

An acquisition authorizes collection only; the agent still enforces its local policy.
There is deliberately no endpoint for arbitrary commands or scripts.
"""
import base64
import hashlib
import math
import os
import re
import time
from pathlib import PurePosixPath, PureWindowsPath

from fastapi import Depends, Request
from fastapi.responses import FileResponse
from sqlalchemy import select, update, and_

from . import db as D
from .crypto import atomic_write, canon, dumps, loads, now, sha, uid
from .service import DomainError, row, rows

CHUNK_BYTES = 4 * 1024 * 1024
TEMPLATES = {"selected-files", "processes", "network", "memory-capture"}
ACTIVE = {"APPROVED", "LEASED", "RUNNING"}


def file_sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def allowed_path(path, roots, platform):
    """Lexical server check. Agents must also reject links and resolve actual paths."""
    cls = PureWindowsPath if str(platform).lower().startswith("win") else PurePosixPath
    p = cls(path)
    if not p.is_absolute() or ".." in p.parts or any(ord(c) < 32 for c in path):
        return False
    return any(p == cls(root) or cls(root) in p.parents for root in roots)


def decoded(item):
    return {**item, "plan": loads(item["plan"], {}), "signed_plan": loads(item["signed_plan"], None), "result": loads(item["result"], {})}


def register_acquisition_routes(app, service, user, admin, investigator, collector, reauthenticate):
    def scoped(c, who, aid, write=False):
        item = row(c, select(D.acquisitions).where(D.acquisitions.c.id == aid))
        if not item:
            raise DomainError("NOT_FOUND", "Acquisition not found", 404)
        service.allowed_case(c, who, item["case_id"], write=write)
        return item

    def agent_job(c, col, aid, require_active=True):
        item = row(c, select(D.acquisitions).where(and_(D.acquisitions.c.id == aid, D.acquisitions.c.collector_id == col["id"])))
        if not item:
            raise DomainError("NOT_FOUND", "Acquisition not found", 404)
        if require_active:
            if item["state"] not in ("LEASED", "RUNNING"):
                raise DomainError("JOB_STATE", "Acquisition is not executing", 409)
            if item["expires"] < time.time() or (item["lease_until"] or 0) < time.time():
                raise DomainError("JOB_EXPIRED", "Acquisition authorization or execution lease expired; review required", 409)
        return item

    def agent_upload(c, col, upload_id, active=True):
        item = row(c, select(D.uploads).where(and_(D.uploads.c.id == upload_id, D.uploads.c.collector_id == col["id"])))
        if not item:
            raise DomainError("NOT_FOUND", "Upload not found", 404)
        agent_job(c, col, item["acquisition_id"], active and item["state"] != "COMPLETE")
        if item["expires"] < time.time() and item["state"] != "COMPLETE":
            raise DomainError("UPLOAD_EXPIRED", "Upload expired", 409)
        return item

    @app.get("/api/v1/acquisitions")
    def list_acquisitions(u=Depends(user)):
        with service.db.read() as c:
            result = []
            for item in rows(c, select(D.acquisitions).order_by(D.acquisitions.c.created_at.desc()).limit(500)):
                try:
                    service.allowed_case(c, u, item["case_id"])
                except DomainError:
                    continue
                result.append(decoded(item))
            return result

    @app.post("/api/v1/acquisitions", status_code=201)
    def propose(body: dict, u=Depends(investigator)):
        template = body.get("template", "selected-files")
        paths = body.get("paths", [])
        reason = str(body.get("reason", "")).strip()
        try:
            max_bytes = int(body.get("max_bytes", 20 * 1024**2))
            timeout = int(body.get("timeout_seconds", 300))
        except (ValueError, TypeError):
            raise DomainError("INVALID_BOUNDS", "Byte and time limits must be integers", 422)
        if template not in TEMPLATES or not isinstance(paths, list) or len(paths) > 100 or not all(isinstance(p, str) and 0 < len(p) <= 1024 for p in paths):
            raise DomainError("INVALID_PLAN", "Use a supported template and at most 100 bounded paths", 422)
        if not 1 <= max_bytes <= service.settings.max_artifact_bytes or not 10 <= timeout <= 3600:
            raise DomainError("INVALID_BOUNDS", "Limits must be 1 byte to 4 GiB and 10 to 3600 seconds", 422)
        if not 10 <= len(reason) <= 2000:
            raise DomainError("REASON_REQUIRED", "Provide a 10–2000 character acquisition reason", 422)
        with service.db.tx() as c:
            case = service.allowed_case(c, u, str(body.get("case_id", "")), write=True)
            if case["status"] == "CLOSED":
                raise DomainError("CASE_CLOSED", "Reopen the case before proposing acquisition", 409)
            col = row(c, select(D.collectors).where(D.collectors.c.id == str(body.get("collector_id", ""))))
            if not col or col["state"] != "ACTIVE":
                raise DomainError("COLLECTOR_UNAVAILABLE", "Choose an active collector", 422)
            asset = row(c, select(D.assets).where(D.assets.c.id == col["asset_id"]))
            config = loads(col["configuration"], {})
            if template == "selected-files" and (not paths or not all(allowed_path(p, config.get("paths", []), asset["os"]) for p in paths)):
                raise DomainError("PATH_SCOPE", "All selected paths must fall inside the collector's configured paths", 422)
            if template != "selected-files" and paths:
                raise DomainError("PATH_SCOPE", "Paths are supported only by selected-files", 422)
            if template == "memory-capture" and not loads(col["health"], {}).get("capabilities", {}).get("memory_capture", False):
                raise DomainError("TOOL_UNAVAILABLE", "This collector has not reported an approved memory capture adapter", 422)
            aid = uid()
            expires = int(time.time()) + 7200
            plan = {"acquisition_id": aid, "case_id": case["id"], "collector_id": col["id"], "template": template, "paths": paths, "max_bytes": max_bytes, "timeout_seconds": timeout, "reason": reason, "created_at": now(), "expires_at": expires, "nonce": uid()}
            c.execute(D.acquisitions.insert().values(id=aid, case_id=case["id"], collector_id=col["id"], actor_id=u["id"], state="PROPOSED", plan=dumps(plan), reason=reason, created_at=now(), updated_at=now(), expires=expires))
            service.audit(c, u["id"], "ACQUISITION_PROPOSED", aid, reason=reason, details={"case_id": case["id"], "plan_sha256": sha(canon(plan))})
        return {"id": aid, "state": "PROPOSED", "plan": plan}

    @app.post("/api/v1/acquisitions/{aid}/approve")
    def approve(aid: str, body: dict, u=Depends(investigator)):
        reauthenticate(u, body.get("password", ""), body.get("otp"))
        with service.db.tx() as c:
            item = scoped(c, u, aid, write=True)
            if item["state"] != "PROPOSED" or item["expires"] < time.time():
                raise DomainError("JOB_STATE", "Only an unexpired proposed acquisition can be approved", 409)
            if item["actor_id"] == u["id"] and not (service.settings.mode == "virtual" and service.settings.allow_self_approval):
                raise DomainError("SEPARATE_APPROVER", "A different assigned investigator or administrator must approve this plan", 403)
            signed = service.signed("CBB-ACQUISITION-v1", loads(item["plan"]))
            c.execute(update(D.acquisitions).where(D.acquisitions.c.id == aid).values(state="APPROVED", approver_id=u["id"], signed_plan=dumps(signed), updated_at=now()))
            service.audit(c, u["id"], "ACQUISITION_APPROVED", aid, details={"plan_sha256": sha(canon(signed)), "self_approval": item["actor_id"] == u["id"]})
        return {"id": aid, "state": "APPROVED", "signed_plan": signed}

    def stop_plan(aid, body, u, rejected=False):
        reason = str(body.get("reason", "")).strip()
        if not 3 <= len(reason) <= 2000:
            raise DomainError("REASON_REQUIRED", "Provide a reason for this decision", 422)
        with service.db.tx() as c:
            item = scoped(c, u, aid, write=True)
            permitted = {"PROPOSED"} if rejected else {"PROPOSED", "APPROVED", "LEASED", "RUNNING", "NEEDS_REVIEW"}
            if item["state"] not in permitted:
                raise DomainError("JOB_STATE", "This acquisition cannot be changed in its current state", 409)
            state = "REJECTED" if rejected else "CANCELLED"
            c.execute(update(D.acquisitions).where(D.acquisitions.c.id == aid).values(state=state, updated_at=now(), result=dumps({"reason": reason, "endpoint_may_have_started": item["state"] in {"LEASED", "RUNNING", "NEEDS_REVIEW"}})))
            service.audit(c, u["id"], "ACQUISITION_" + state, aid, reason=reason)
        return {"id": aid, "state": state}

    @app.post("/api/v1/acquisitions/{aid}/reject")
    def reject(aid: str, body: dict, u=Depends(investigator)):
        return stop_plan(aid, body, u, True)

    @app.post("/api/v1/acquisitions/{aid}/cancel")
    def cancel(aid: str, body: dict, u=Depends(investigator)):
        return stop_plan(aid, body, u)

    @app.get("/api/v1/collector-jobs")
    def lease(col=Depends(collector)):
        with service.db.tx() as c:
            # A lease is never reissued automatically: reboot/interruption needs human review.
            for item in rows(c, select(D.acquisitions).where(and_(D.acquisitions.c.collector_id == col["id"], D.acquisitions.c.state.in_(["APPROVED", "LEASED", "RUNNING"])))):
                if item["expires"] < time.time() or (item["state"] != "APPROVED" and (item["lease_until"] or 0) < time.time()):
                    state = "EXPIRED" if item["state"] == "APPROVED" else "NEEDS_REVIEW"
                    c.execute(update(D.acquisitions).where(D.acquisitions.c.id == item["id"]).values(state=state, updated_at=now()))
                    service.audit(c, col["id"], "ACQUISITION_" + state, item["id"])
            item = row(c, select(D.acquisitions).where(and_(D.acquisitions.c.collector_id == col["id"], D.acquisitions.c.state == "APPROVED")).order_by(D.acquisitions.c.created_at).limit(1))
            if not item:
                return {"job": None}
            plan = loads(item["plan"])
            until = min(item["expires"], time.time() + plan["timeout_seconds"] + 900)
            c.execute(update(D.acquisitions).where(D.acquisitions.c.id == item["id"]).values(state="LEASED", lease_until=until, updated_at=now()))
            service.audit(c, col["id"], "ACQUISITION_LEASED", item["id"])
            return {"job": {"id": item["id"], "signed_plan": loads(item["signed_plan"]), "lease_until": until}}

    @app.post("/api/v1/collector-jobs/{aid}/status")
    def status(aid: str, body: dict, col=Depends(collector)):
        state = body.get("state")
        if state not in {"RUNNING", "COMPLETE", "FAILED"}:
            raise DomainError("JOB_STATE", "Use RUNNING, COMPLETE or FAILED", 422)
        with service.db.tx() as c:
            item = agent_job(c, col, aid, require_active=False)
            if item["state"] == state and state in {"COMPLETE", "FAILED"}:
                return {"id": aid, "state": state, "result": loads(item["result"], {})}
            agent_job(c, col, aid)
            complete = rows(c, select(D.uploads).where(and_(D.uploads.c.acquisition_id == aid, D.uploads.c.state == "COMPLETE")))
            if state == "COMPLETE" and not complete:
                raise DomainError("ARTIFACT_REQUIRED", "Complete a verified artifact upload first", 409)
            result = {"detail": str(body.get("detail", ""))[:2000], "artifact_ids": [x["artifact_id"] for x in complete]}
            c.execute(update(D.acquisitions).where(D.acquisitions.c.id == aid).values(state=state, result=dumps(result), updated_at=now()))
            service.audit(c, col["id"], "ACQUISITION_" + state, aid, "ERROR" if state == "FAILED" else "SUCCESS", details=result)
            return {"id": aid, "state": state, "result": result}

    @app.post("/api/v1/uploads", status_code=201)
    def begin_upload(body: dict, col=Depends(collector)):
        name = str(body.get("name", ""))
        digest = str(body.get("sha256", ""))
        try:
            size = int(body.get("size", -1))
        except (ValueError, TypeError):
            raise DomainError("UPLOAD_SIZE", "Artifact size must be an integer", 422)
        if not name or len(name) > 200 or PureWindowsPath(name).name != name or PurePosixPath(name).name != name or name in {".", ".."} or any(ord(x) < 32 for x in name):
            raise DomainError("UPLOAD_NAME", "Provide a file name without a path", 422)
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise DomainError("UPLOAD_HASH", "Provide the complete file SHA-256", 422)
        with service.db.tx() as c:
            item = agent_job(c, col, str(body.get("acquisition_id", "")))
            existing = rows(c, select(D.uploads).where(D.uploads.c.acquisition_id == item["id"]))
            for old in existing:
                if old["name"] == name and old["size"] == size and old["sha256"] == digest:
                    return {"upload_id": old["id"], "chunk_bytes": CHUNK_BYTES, "state": old["state"], "received_parts": sorted(int(i) for i in loads(old["parts"], {}))}
            plan = loads(item["plan"])
            if size < 0 or size > service.settings.max_artifact_bytes or sum(x["size"] for x in existing) + size > plan["max_bytes"] or len(existing) >= 100:
                raise DomainError("UPLOAD_SIZE", "Artifact transfer exceeds the approved total size or count", 413)
            upload_id = uid()
            (service.root / "uploads" / upload_id).mkdir(exist_ok=True)
            c.execute(D.uploads.insert().values(id=upload_id, acquisition_id=item["id"], collector_id=col["id"], name=name, size=size, sha256=digest, parts="{}", state="UPLOADING", expires=min(item["expires"], item["lease_until"])))
            service.audit(c, col["id"], "ARTIFACT_UPLOAD_STARTED", item["id"], details={"upload_id": upload_id, "size": size, "sha256": digest})
        return {"upload_id": upload_id, "chunk_bytes": CHUNK_BYTES, "state": "UPLOADING", "received_parts": []}

    @app.get("/api/v1/uploads/{upload_id}")
    def upload_status(upload_id: str, col=Depends(collector)):
        with service.db.read() as c:
            item = agent_upload(c, col, upload_id)
            return {"upload_id": upload_id, "state": item["state"], "chunk_bytes": CHUNK_BYTES, "received_parts": sorted(int(i) for i in loads(item["parts"], {})), "artifact_id": item["artifact_id"]}

    @app.put("/api/v1/uploads/{upload_id}/chunks/{index}")
    async def chunk(upload_id: str, index: int, request: Request, col=Depends(collector)):
        data = await request.body()
        if index < 0 or len(data) > CHUNK_BYTES:
            raise DomainError("CHUNK_SIZE", "Invalid chunk index or size", 413)
        with service.db.tx() as c:
            item = agent_upload(c, col, upload_id)
            if item["state"] != "UPLOADING":
                raise DomainError("UPLOAD_STATE", "Upload no longer accepts chunks", 409)
            count = math.ceil(item["size"] / CHUNK_BYTES)
            expected = min(CHUNK_BYTES, item["size"] - index * CHUNK_BYTES)
            if index >= count or len(data) != expected:
                raise DomainError("CHUNK_SIZE", "Chunk does not match the declared artifact size", 422)
            parts = loads(item["parts"], {})
            digest = sha(data)
            if str(index) in parts:
                if parts[str(index)] != digest:
                    raise DomainError("CHUNK_CONFLICT", "Chunk index already contains different bytes", 409)
                return {"index": index, "sha256": digest, "duplicate": True}
            atomic_write(service.root / "uploads" / upload_id / (str(index) + ".part"), data)
            parts[str(index)] = digest
            c.execute(update(D.uploads).where(D.uploads.c.id == upload_id).values(parts=dumps(parts)))
        return {"index": index, "sha256": digest, "duplicate": False}

    @app.post("/api/v1/uploads/{upload_id}/complete")
    def finish(upload_id: str, col=Depends(collector)):
        # Serializes completion in this single-writer deployment and supports safe retry.
        with service.db.lock:
            with service.db.tx() as c:
                item = agent_upload(c, col, upload_id)
                if item["state"] == "COMPLETE":
                    artifact = row(c, select(D.artifacts).where(D.artifacts.c.id == item["artifact_id"]))
                    return {"artifact_id": artifact["id"], "evidence_id": artifact["evidence_id"], "duplicate": True}
                job = agent_job(c, col, item["acquisition_id"])
                parts = loads(item["parts"], {})
                if set(parts) != {str(i) for i in range(math.ceil(item["size"] / CHUNK_BYTES))}:
                    raise DomainError("MISSING_CHUNKS", "Upload is incomplete", 409)
                c.execute(update(D.uploads).where(D.uploads.c.id == upload_id).values(state="FINALIZING"))
            destination = service.root / "artifacts" / (upload_id + ".bin")
            tmp = destination.with_suffix(".pending")
            digest = hashlib.sha256()
            size = 0
            with tmp.open("wb") as f:
                for i in range(len(parts)):
                    data = (service.root / "uploads" / upload_id / (str(i) + ".part")).read_bytes()
                    if sha(data) != parts[str(i)]:
                        raise DomainError("CHUNK_MODIFIED", "Stored chunk no longer matches its transfer hash", 409)
                    f.write(data); digest.update(data); size += len(data)
                f.flush(); os.fsync(f.fileno())
            if size != item["size"] or digest.hexdigest() != item["sha256"]:
                tmp.unlink(missing_ok=True)
                with service.db.tx() as c:
                    c.execute(update(D.uploads).where(D.uploads.c.id == upload_id).values(state="HASH_FAILED"))
                    service.audit(c, col["id"], "ARTIFACT_HASH_FAILED", job["id"], "ERROR", details={"upload_id": upload_id})
                raise DomainError("ARTIFACT_HASH", "Complete artifact hash or byte count does not match", 409)
            os.replace(tmp, destination)
            raw = canon({"artifact_id": upload_id, "acquisition_id": job["id"], "name": item["name"], "size": str(size), "sha256": item["sha256"], "signed_plan_sha256": sha(canon(loads(job["signed_plan"]))), "summary": "Verified acquisition artifact: " + item["name"]})
            wire = {"boot_id": "acquisition:" + job["id"], "source_seq": str(int(upload_id.replace("-", "")[:14], 16)), "source_type": "acquisition", "event_type": "acquisition.artifact", "collected_at": job["created_at"], "original_timestamp": None, "raw_media_type": "application/json", "raw_base64": base64.b64encode(raw).decode(), "raw_sha256": sha(raw), "source_cursor": {"upload_id": upload_id}}
            receipt = service.accept(col, [wire])[0]
            if receipt["outcome"] not in {"accepted", "duplicate"}:
                raise DomainError("PRESERVATION_FAILED", "Artifact metadata could not enter the evidence ledger", 409)
            evidence_id = receipt["evidence_id"]
            for _ in range(100):
                service.seal_pending(1000)
                with service.db.read() as c:
                    sealed = row(c, select(D.evidence.c.id).where(D.evidence.c.id == evidence_id))
                if sealed:
                    break
            if not sealed:
                raise DomainError("PRESERVATION_PENDING", "Artifact bytes are safe; metadata is awaiting sealing. Retry completion.", 503)
            with service.db.tx() as c:
                if not row(c, select(D.artifacts).where(D.artifacts.c.id == upload_id)):
                    c.execute(D.artifacts.insert().values(id=upload_id, path="artifacts/" + destination.name, name=item["name"], size=size, sha256=item["sha256"], evidence_id=evidence_id, case_id=job["case_id"], created_at=now()))
                    case = row(c, select(D.cases).where(D.cases.c.id == job["case_id"]))
                    version = case["version"] + 1
                    c.execute(D.case_evidence.insert().values(id=uid(), case_id=case["id"], evidence_id=evidence_id, case_version=version, active=True, reason="Approved acquisition " + job["id"], created_at=now()))
                    c.execute(update(D.cases).where(D.cases.c.id == case["id"]).values(version=version, updated_at=now()))
                    service.audit(c, col["id"], "ARTIFACT_REGISTERED", case["id"], details={"artifact_id": upload_id, "evidence_id": evidence_id, "sha256": item["sha256"]})
                c.execute(update(D.uploads).where(D.uploads.c.id == upload_id).values(state="COMPLETE", artifact_id=upload_id))
            return {"artifact_id": upload_id, "evidence_id": evidence_id, "duplicate": False}

    @app.get("/api/v1/artifacts")
    def artifacts(u=Depends(user)):
        with service.db.read() as c:
            result = []
            for item in rows(c, select(D.artifacts).order_by(D.artifacts.c.created_at.desc()).limit(500)):
                try:
                    service.allowed_case(c, u, item["case_id"])
                except DomainError:
                    continue
                item.pop("path")
                result.append(item)
            return result

    @app.get("/api/v1/artifacts/{artifact_id}/download")
    def download(artifact_id: str, u=Depends(user)):
        with service.db.tx() as c:
            item = row(c, select(D.artifacts).where(D.artifacts.c.id == artifact_id))
            if not item:
                raise DomainError("NOT_FOUND", "Artifact not found", 404)
            service.allowed_case(c, u, item["case_id"])
            if u["role"] == "auditor":
                raise DomainError("FORBIDDEN", "Auditor cannot download raw artifacts", 403)
            path = service.root / item["path"]
            if not path.is_file() or path.stat().st_size != item["size"] or file_sha(path) != item["sha256"]:
                raise DomainError("ARTIFACT_MODIFIED", "Artifact no longer matches its preserved digest", 409)
            service.audit(c, u["id"], "ARTIFACT_DOWNLOAD_STARTED", item["case_id"], details={"artifact_id": artifact_id, "sha256": item["sha256"]})
        return FileResponse(path, media_type="application/octet-stream", filename=item["name"])
