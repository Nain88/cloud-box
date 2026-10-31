"""Explicit offline imports and bounded, installed-tool adapters."""
import base64
import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path

from fastapi import Depends, Request
from sqlalchemy import select, update, and_

from . import db as D
from .crypto import atomic_write, canon, dumps, loads, now, sha, strict_json, uid
from .schema import parse_time
from .service import DomainError, row, rows

IMPORT_SOURCES = {"windows.event", "linux.journal", "suricata.eve", "zeek", "fim", "yara", "collector.health", "lab.fixture"}


def imported_collector(service, actor_id, case_id, name, input_hash):
    identity = sha(canon({"actor_id": actor_id, "case_id": case_id, "name": name, "sha256": input_hash}))
    col_id = identity[:32]
    with service.db.tx() as c:
        existing = row(c, select(D.collectors).where(D.collectors.c.id == col_id))
        if existing:
            return existing
        asset_id = uid()
        c.execute(D.assets.insert().values(id=asset_id, name="Imported: " + name[:120], os="offline-import", criticality=3))
        c.execute(D.collectors.insert().values(id=col_id, asset_id=asset_id, name="Offline import: " + name[:120], token_hash=sha(os.urandom(32)), state="ACTIVE", created_at=now(), health=dumps({"kind": "offline-import", "live_sensor": False}), configuration=dumps({"paths": [], "import_sha256": input_hash}), config_version=1))
        return row(c, select(D.collectors).where(D.collectors.c.id == col_id))


def link_evidence(service, actor_id, case_id, evidence_ids, reason):
    with service.db.tx() as c:
        case = row(c, select(D.cases).where(D.cases.c.id == case_id))
        if not case:
            raise DomainError("CASE_UNAVAILABLE", "Import case no longer exists", 409)
        existing = {r["evidence_id"] for r in rows(c, select(D.case_evidence.c.evidence_id).where(and_(D.case_evidence.c.case_id == case_id, D.case_evidence.c.active == True)))}
        additions = [eid for eid in evidence_ids if eid not in existing]
        if additions:
            version = case["version"] + 1
            for eid in additions:
                c.execute(D.case_evidence.insert().values(id=uid(), case_id=case_id, evidence_id=eid, case_version=version, active=True, reason=reason, created_at=now()))
            c.execute(update(D.cases).where(D.cases.c.id == case_id).values(version=version, updated_at=now()))
            service.audit(c, actor_id, "IMPORT_LINKED", case_id, reason=reason, details={"evidence_ids": additions, "case_version": version})


def seal_and_link(service, collector, events, actor_id, case_id, reason):
    outcomes = []
    for offset in range(0, len(events), 100):
        outcomes.extend(service.accept(collector, events[offset:offset + 100]))
    ids = [x["evidence_id"] for x in outcomes if x["outcome"] in {"accepted", "duplicate"}]
    for _ in range(100):
        service.seal_pending(1000)
        with service.db.read() as c:
            remaining = rows(c, select(D.receipts.c.id).where(and_(D.receipts.c.evidence_id.in_(ids), D.receipts.c.state == "STAGED"))) if ids else []
        if not remaining:
            break
    with service.db.read() as c:
        preserved = [r["id"] for r in rows(c, select(D.evidence.c.id).where(D.evidence.c.id.in_(ids)))] if ids else []
    link_evidence(service, actor_id, case_id, preserved, reason)
    rejected = [x for x in outcomes if x["outcome"] not in {"accepted", "duplicate"}]
    return {"evidence_ids": preserved, "preserved": len(preserved), "accepted": sum(x["outcome"] == "accepted" for x in outcomes), "duplicates": sum(x["outcome"] == "duplicate" for x in outcomes), "rejected": rejected, "not_sealed": len(ids) - len(preserved)}


def import_bytes(service, actor_id, case_id, name, source, fmt, content, provenance=None, limit=1024 * 1024):
    if source not in IMPORT_SOURCES or fmt not in {"jsonl", "xml", "text"}:
        raise DomainError("IMPORT_FORMAT", "Choose a supported source and jsonl, xml or text format", 422)
    if not content or len(content) > limit:
        raise DomainError("IMPORT_SIZE", "Import is empty or exceeds its size limit", 413)
    input_hash = sha(content)
    col = imported_collector(service, actor_id, case_id, name, input_hash)
    records = content.splitlines(keepends=True) if fmt in {"jsonl", "text"} else [content]
    if len(records) > 100000:
        raise DomainError("IMPORT_COUNT", "Import exceeds 100,000 records", 413)
    # Freeze import observation time for idempotent re-import of exactly the same bytes.
    collected_at = col["created_at"]
    events = []
    for number, raw in enumerate(records, 1):
        if not raw.strip():
            continue
        if len(raw) > service.settings.max_event_bytes:
            raise DomainError("EVENT_SIZE", "Record " + str(number) + " exceeds 64 KiB; acquire large source files as artifacts", 413)
        timestamp = None
        event_type = {"windows.event": "windows.event", "linux.journal": "journal.event", "suricata.eve": "network.event", "zeek": "network.zeek", "fim": "fim.observation", "yara": "yara.match", "lab.fixture": "lab.import", "collector.health": "collector.health"}[source]
        if fmt == "jsonl":
            try:
                parsed = strict_json(raw)
            except (ValueError, UnicodeError) as ex:
                raise DomainError("IMPORT_JSON", f"Record {number} is not strict JSON: {str(ex)[:160]}", 422)
            if not isinstance(parsed, dict):
                raise DomainError("IMPORT_JSON", f"Record {number} must be an object", 422)
            timestamp = parse_time(parsed.get("timestamp") or parsed.get("occurred_at"))
            if source == "linux.journal" and parsed.get("__REALTIME_TIMESTAMP"):
                from datetime import datetime, timezone
                try:
                    timestamp = datetime.fromtimestamp(int(parsed["__REALTIME_TIMESTAMP"]) / 1000000, timezone.utc).isoformat()
                except (ValueError, OverflowError, OSError):
                    timestamp = None
            if source != "suricata.eve":
                event_type = str(parsed.get("event_type", event_type))[:120]
        elif fmt == "xml":
            # A native Windows XML representation is evidence; it is not the EVTX binary.
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise DomainError("IMPORT_XML", "DTD and entity declarations are not accepted", 422)
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                raise DomainError("IMPORT_XML", "Invalid event XML", 422)
            if root.tag.split("}")[-1] != "Event":
                raise DomainError("IMPORT_XML", "Import one Event element per XML file; use the agent for event streams", 422)
        events.append({"boot_id": "import:" + input_hash[:48], "source_seq": str(number), "source_type": source, "event_type": event_type, "collected_at": collected_at, "original_timestamp": timestamp, "raw_media_type": "application/json" if fmt == "jsonl" else "application/xml" if fmt == "xml" else "text/plain", "raw_base64": base64.b64encode(raw).decode(), "raw_sha256": sha(raw), "source_cursor": {"imported": True, "input_name": name, "input_sha256": input_hash, "record": number, **(provenance or {})}})
    result = seal_and_link(service, col, events, actor_id, case_id, "Authorized offline import: " + name)
    with service.db.tx() as c:
        service.audit(c, actor_id, "LOG_IMPORT_COMPLETED", case_id, "PARTIAL" if result["rejected"] or result["not_sealed"] else "SUCCESS", details={"name": name, "input_sha256": input_hash, "source": source, "preserved": result["preserved"], "rejected": len(result["rejected"]), "not_sealed": result["not_sealed"]})
    return {**result, "collector_id": col["id"], "input_sha256": input_hash, "scope": "offline import; not a live endpoint sensor"}


def bounded_process(command, cwd, timeout=300, max_output=256 * 1024**2):
    """Run a fixed tool invocation without a shell and stop on time/output limits."""
    output = Path(cwd)
    log_path = output / "tool.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, cwd=output, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        start = time.monotonic()
        try:
            while process.poll() is None:
                total = sum(p.stat().st_size for p in output.iterdir() if p.is_file())
                if time.monotonic() - start > timeout or total > max_output:
                    process.kill(); process.wait(timeout=10)
                    raise DomainError("TOOL_LIMIT", "Analysis exceeded its time or output limit", 422)
                time.sleep(.15)
        except BaseException:
            if process.poll() is None:
                process.kill(); process.wait(timeout=10)
            raise
    if process.returncode:
        tail = log_path.read_bytes()[-2000:].decode("utf-8", errors="replace")
        raise DomainError("TOOL_FAILED", "Analysis tool exited with code " + str(process.returncode) + ": " + tail, 422)
    return log_path


def preserve_pcap(service, payload):
    """Register the uploaded original before running the optional parser."""
    artifact_id = payload["artifact_id"]
    with service.db.read() as c:
        old = row(c, select(D.artifacts).where(D.artifacts.c.id == artifact_id))
    if old:
        return old
    source = service.root / payload["path"]
    from .acquisition import file_sha
    if file_sha(source) != payload["sha256"] or source.stat().st_size != payload["size"]:
        raise DomainError("PCAP_HASH", "Uploaded PCAP no longer matches its received hash", 409)
    dest = service.root / "artifacts" / (artifact_id + ".pcap")
    if not dest.exists():
        shutil.copyfile(source, dest)
        with dest.open("r+b") as f:
            os.fsync(f.fileno())
    if file_sha(dest) != payload["sha256"]:
        raise DomainError("PCAP_HASH", "Preserved PCAP digest does not match", 409)
    col = imported_collector(service, payload["actor_id"], payload["case_id"], payload["name"], payload["sha256"])
    raw = canon({"artifact_id": artifact_id, "name": payload["name"], "size": str(payload["size"]), "sha256": payload["sha256"], "summary": "Uploaded original PCAP: " + payload["name"], "source": "authorized offline upload"})
    event = {"boot_id": "pcap:" + artifact_id, "source_seq": "0", "source_type": "acquisition", "event_type": "acquisition.artifact", "collected_at": col["created_at"], "raw_media_type": "application/json", "raw_base64": base64.b64encode(raw).decode(), "raw_sha256": sha(raw), "source_cursor": {"input_pcap_sha256": payload["sha256"]}}
    result = seal_and_link(service, col, [event], payload["actor_id"], payload["case_id"], "Authorized PCAP upload")
    if result["preserved"] != 1:
        raise DomainError("PCAP_PRESERVATION", "PCAP metadata is awaiting durable preservation", 503)
    with service.db.tx() as c:
        if not row(c, select(D.artifacts.c.id).where(D.artifacts.c.id == artifact_id)):
            c.execute(D.artifacts.insert().values(id=artifact_id, path="artifacts/" + dest.name, name=payload["name"], size=payload["size"], sha256=payload["sha256"], evidence_id=result["evidence_ids"][0], case_id=payload["case_id"], created_at=now()))
            service.audit(c, payload["actor_id"], "PCAP_PRESERVED", payload["case_id"], details={"artifact_id": artifact_id, "sha256": payload["sha256"]})
        return row(c, select(D.artifacts).where(D.artifacts.c.id == artifact_id))


def process_pcap(service, payload):
    artifact = preserve_pcap(service, payload)
    result_key = "pcap-result:" + payload["artifact_id"]
    with service.db.read() as c:
        prior = row(c, select(D.config).where(D.config.c.id == result_key))
    if prior:
        return loads(prior["value"])
    executable = os.getenv("CBB_SURICATA_EXECUTABLE") or shutil.which("suricata")
    config = os.getenv("CBB_SURICATA_CONFIG", "")
    if not executable or not Path(executable).is_file():
        raise DomainError("TOOL_UNAVAILABLE", "PCAP is preserved. Install Suricata and set CBB_SURICATA_EXECUTABLE to its absolute path for offline analysis.", 422)
    if not config or not Path(config).is_absolute() or not Path(config).is_file():
        raise DomainError("TOOL_CONFIGURATION", "PCAP is preserved. Set CBB_SURICATA_CONFIG to a reviewed Suricata YAML file.", 422)
    executable = str(Path(executable).resolve())
    out = service.root / "inbox" / (payload["artifact_id"] + "-analysis")
    out.mkdir(exist_ok=True)
    complete_marker = out / "analysis-complete.json"
    if not complete_marker.exists():
        # A fresh directory avoids appending duplicate EVE lines after an interrupted tool run.
        run = out / uid()
        run.mkdir()
        bounded_process([executable, "-c", str(Path(config).resolve()), "-r", str((service.root / artifact["path"]).resolve()), "-l", str(run.resolve()), "-k", "none", "--runmode", "single"], run, timeout=300)
        eve = run / "eve.json"
        if not eve.is_file():
            raise DomainError("EVE_UNAVAILABLE", "Suricata completed but did not create eve.json; enable EVE JSON in its reviewed configuration", 422)
        atomic_write(complete_marker, canon({"eve": str(eve.relative_to(service.root)), "sha256": sha(eve.read_bytes()), "config_sha256": sha(Path(config).read_bytes())}))
    marker = loads(complete_marker.read_bytes())
    eve = service.root / marker["eve"]
    content = eve.read_bytes()
    if sha(content) != marker["sha256"]:
        raise DomainError("EVE_MODIFIED", "Offline analysis output changed before import", 409)
    result = import_bytes(service, payload["actor_id"], payload["case_id"], payload["name"] + " EVE", "suricata.eve", "jsonl", content, {"input_pcap_sha256": payload["sha256"], "artifact_id": artifact["id"], "tool": "suricata", "config_sha256": marker["config_sha256"]}, limit=256 * 1024**2) if content.strip() else {"preserved": 0, "evidence_ids": [], "note": "Suricata emitted no EVE records for this capture"}
    result.update({"artifact_id": artifact["id"], "pcap_sha256": payload["sha256"], "scope": "offline PCAP; visibility limited to captured traffic"})
    with service.db.tx() as c:
        c.execute(D.config.insert().values(id=result_key, value=dumps(result), version=1, updated_at=now()))
        service.audit(c, payload["actor_id"], "PCAP_ANALYZED", payload["case_id"], details={"artifact_id": artifact["id"], "records": result["preserved"]})
    return result


def register_import_routes(app, service, admin):
    @app.post("/api/v1/imports", status_code=201)
    def import_logs(body: dict, u=Depends(admin)):
        case_id = str(body.get("case_id", ""))
        with service.db.read() as c:
            case = service.allowed_case(c, u, case_id, write=True)
            if case["status"] == "CLOSED":
                raise DomainError("CASE_CLOSED", "Reopen the case before importing evidence", 409)
        name = str(body.get("name", "import.log"))[:200]
        if "content_base64" in body:
            try:
                content = base64.b64decode(body["content_base64"], validate=True)
            except (ValueError, TypeError):
                raise DomainError("IMPORT_ENCODING", "Invalid base64 content", 422)
        else:
            content = str(body.get("content", "")).encode("utf-8")
        return import_bytes(service, u["id"], case_id, name, body.get("source_type", "lab.fixture"), body.get("format", "jsonl"), content)

    @app.post("/api/v1/pcaps", status_code=202)
    async def pcap(request: Request, u=Depends(admin)):
        form = await request.form(max_files=1, max_fields=2)
        file = form.get("file")
        if file is None or not hasattr(file, "read"):
            raise DomainError("PCAP_REQUIRED", "Upload a PCAP file", 422)
        case_id = str(form.get("case_id", ""))
        with service.db.read() as c:
            case = service.allowed_case(c, u, case_id, write=True)
            if case["status"] == "CLOSED":
                raise DomainError("CASE_CLOSED", "Reopen the case before importing PCAP", 409)
        artifact_id = uid()
        path = service.root / "inbox" / (artifact_id + ".pcap")
        digest = hashlib.sha256()
        size = 0
        with path.open("wb") as f:
            while True:
                block = await file.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > 256 * 1024**2:
                    raise DomainError("PCAP_SIZE", "PCAP exceeds the 256 MiB offline analysis limit", 413)
                if size == len(block) and block[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
                    raise DomainError("PCAP_FORMAT", "File does not have a PCAP or PCAPNG header", 422)
                f.write(block); digest.update(block)
            f.flush(); os.fsync(f.fileno())
        if size < 24:
            raise DomainError("PCAP_FORMAT", "PCAP is empty or truncated", 422)
        payload = {"artifact_id": artifact_id, "actor_id": u["id"], "case_id": case_id, "name": Path(str(file.filename or "capture.pcap")).name[:200], "path": str(path.relative_to(service.root)).replace("\\", "/"), "sha256": digest.hexdigest(), "size": size}
        # Preservation occurs before optional parsing so missing tools cannot lose the upload.
        preserve_pcap(service, payload)
        with service.db.tx() as c:
            jid = service.create_job(c, "pcap", u["id"], payload, case_id, operation_key="pcap:" + artifact_id)
        return {"job_id": jid, "artifact_id": artifact_id, "sha256": payload["sha256"], "size": size}

