import base64
from datetime import datetime, timedelta, timezone
import json
import struct

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from cbb import db as D
from cbb.api import create_app
from cbb.config import Settings
from cbb.crypto import canon, dumps, sha, verify_signature
from cbb.service import DomainError, row
from cbb.analytics import train, score


PASSWORD = "test-only-strong-password-45822"


@pytest.fixture
def feature_app(tmp_path):
    app = create_app(Settings(data=tmp_path / "server", workers=False))
    service = app.state.service
    with TestClient(app) as client:
        assert client.post("/api/v1/admin/setup", json={"token": service.bootstrap_file.read_text(), "username": "admin", "password": PASSWORD}).status_code == 200
        login = client.post("/api/v1/auth/session", json={"username": "admin", "password": PASSWORD}).json()
        client.headers["x-csrf-token"] = login["csrf"]
        case_id = client.get("/api/v1/cases").json()[0]["id"]
        token = client.post("/api/v1/enrollments", json={"name": "fixture endpoint", "os": "Windows"}).json()["token"]
        enrollment = client.post("/api/v1/collectors/enroll", json={"token": token}).json()
        client.put("/api/v1/collectors/" + enrollment["collector_id"] + "/configuration", json={"paths": ["C:\\Evidence"]})
        yield app, service, client, case_id, enrollment


def proposed(client, case_id, enrollment, **changes):
    payload = {"case_id": case_id, "collector_id": enrollment["collector_id"], "template": "selected-files", "paths": ["C:\\Evidence\\example.txt"], "max_bytes": 1024, "timeout_seconds": 300, "reason": "Authorized fixture acquisition"}
    payload.update(changes)
    return client.post("/api/v1/acquisitions", json=payload)


def approve_other(app, client, case_id, acquisition_id):
    user_id = client.post("/api/v1/users", json={"username": "second", "password": PASSWORD, "role": "investigator"}).json()["id"]
    assert client.post(f"/api/v1/cases/{case_id}/members", json={"user_id": user_id}).status_code == 200
    with TestClient(app) as second:
        session = second.post("/api/v1/auth/session", json={"username": "second", "password": PASSWORD}).json()
        second.headers["x-csrf-token"] = session["csrf"]
        return second.post(f"/api/v1/acquisitions/{acquisition_id}/approve", json={"password": PASSWORD})


def agent_client(app, enrollment):
    return TestClient(app, headers={"authorization": "Bearer " + enrollment["token"]})


def test_acquisition_preserves_verified_artifact_and_case(feature_app):
    app, service, client, case_id, enrollment = feature_app
    created = proposed(client, case_id, enrollment)
    assert created.status_code == 201, created.text
    aid = created.json()["id"]
    denied = client.post(f"/api/v1/acquisitions/{aid}/approve", json={"password": PASSWORD})
    assert denied.status_code == 403 and denied.json()["code"] == "SEPARATE_APPROVER"
    approved = approve_other(app, client, case_id, aid)
    assert approved.status_code == 200, approved.text
    plan = verify_signature(approved.json()["signed_plan"], "CBB-ACQUISITION-v1", service.deployment["public_key"])
    assert plan["paths"] == ["C:\\Evidence\\example.txt"]
    # Do not enter another app lifespan here: restart deliberately marks leased work for review.
    agent = agent_client(app, enrollment)
    job = agent.get("/api/v1/collector-jobs").json()["job"]
    assert job["id"] == aid
    assert agent.get("/api/v1/collector-jobs").json() == {"job": None}
    assert agent.post(f"/api/v1/collector-jobs/{aid}/status", json={"state": "COMPLETE"}).status_code == 409
    assert agent.post(f"/api/v1/collector-jobs/{aid}/status", json={"state": "RUNNING"}).status_code == 200
    data = b"Evidence bytes\x00\r\nnot normalized"
    upload = agent.post("/api/v1/uploads", json={"acquisition_id": aid, "name": "example.txt", "size": len(data), "sha256": sha(data)}).json()
    upid = upload["upload_id"]
    assert agent.put(f"/api/v1/uploads/{upid}/chunks/0", content=data).status_code == 200
    conflict = agent.put(f"/api/v1/uploads/{upid}/chunks/0", content=b"X" * len(data))
    assert conflict.status_code == 409 and conflict.json()["code"] == "CHUNK_CONFLICT"
    finished = agent.post(f"/api/v1/uploads/{upid}/complete")
    assert finished.status_code == 200, finished.text
    artifact_id = finished.json()["artifact_id"]
    assert agent.post(f"/api/v1/uploads/{upid}/complete").json()["duplicate"]
    assert agent.post(f"/api/v1/collector-jobs/{aid}/status", json={"state": "COMPLETE"}).status_code == 200
    assert agent.post(f"/api/v1/collector-jobs/{aid}/status", json={"state": "COMPLETE"}).status_code == 200
    assert client.get(f"/api/v1/artifacts/{artifact_id}/download").content == data
    detail = client.get(f"/api/v1/cases/{case_id}").json()
    assert finished.json()["evidence_id"] in [e["id"] for e in detail["evidence"]]
    with service.db.read() as c:
        artifact = row(c, select(D.artifacts).where(D.artifacts.c.id == artifact_id))
    (service.root / artifact["path"]).write_bytes(b"tampered")
    assert client.get(f"/api/v1/artifacts/{artifact_id}/download").status_code == 409


def test_acquisition_scope_memory_and_expiry(feature_app):
    app, service, client, case_id, enrollment = feature_app
    for path in ("C:\\Windows\\secret", "C:\\Evidence\\..\\Windows\\secret", "relative.txt"):
        assert proposed(client, case_id, enrollment, paths=[path]).status_code == 422
    assert proposed(client, case_id, enrollment, template="run-command", paths=[]).status_code == 422
    memory = proposed(client, case_id, enrollment, template="memory-capture", paths=[])
    assert memory.status_code == 422 and memory.json()["code"] == "TOOL_UNAVAILABLE"
    aid = proposed(client, case_id, enrollment).json()["id"]
    approve_other(app, client, case_id, aid)
    with service.db.tx() as c:
        c.execute(update(D.acquisitions).where(D.acquisitions.c.id == aid).values(expires=1))
    agent = agent_client(app, enrollment)
    assert agent.get("/api/v1/collector-jobs").json() == {"job": None}
    assert next(x for x in client.get("/api/v1/acquisitions").json() if x["id"] == aid)["state"] == "EXPIRED"


def test_upload_hash_and_cancellation(feature_app):
    app, service, client, case_id, enrollment = feature_app
    aid = proposed(client, case_id, enrollment).json()["id"]
    approve_other(app, client, case_id, aid)
    agent = agent_client(app, enrollment)
    agent.get("/api/v1/collector-jobs")
    bad = agent.post("/api/v1/uploads", json={"acquisition_id": aid, "name": "../bad", "size": 4, "sha256": sha(b"test")})
    assert bad.status_code == 422
    upload = agent.post("/api/v1/uploads", json={"acquisition_id": aid, "name": "test.bin", "size": 4, "sha256": sha(b"good")}).json()["upload_id"]
    assert agent.post(f"/api/v1/uploads/{upload}/complete").status_code == 409
    assert agent.put(f"/api/v1/uploads/{upload}/chunks/0", content=b"evil").status_code == 200
    bad = agent.post(f"/api/v1/uploads/{upload}/complete")
    assert bad.status_code == 409 and bad.json()["code"] == "ARTIFACT_HASH"
    assert client.post(f"/api/v1/acquisitions/{aid}/cancel", json={"reason": "Stop requested by owner"}).status_code == 200
    assert agent.post(f"/api/v1/collector-jobs/{aid}/status", json={"state": "RUNNING"}).status_code == 409


def test_import_exact_bytes_dedup_and_scope(feature_app):
    app, service, client, case_id, enrollment = feature_app
    raw = b'{"event_type":"process.create","process":"demo","severity":2}\r\n'
    payload = {"case_id": case_id, "name": "raw.jsonl", "source_type": "lab.fixture", "format": "jsonl", "content_base64": base64.b64encode(raw).decode()}
    imported = client.post("/api/v1/imports", json=payload)
    assert imported.status_code == 201, imported.text
    item = imported.json()
    assert item["preserved"] == 1
    assert client.get("/api/v1/evidence/" + item["evidence_ids"][0] + "/raw").content == raw
    again = client.post("/api/v1/imports", json=payload).json()
    assert again["duplicates"] == 1 and again["accepted"] == 0
    invalid = client.post("/api/v1/imports", json={**payload, "content_base64": base64.b64encode(b'{"a":1,"a":2}').decode()})
    assert invalid.status_code == 422
    foreign = client.post("/api/v1/imports", json={**payload, "case_id": "unassigned"})
    assert foreign.status_code == 404


def test_pcap_preserved_when_optional_tool_is_missing(feature_app, monkeypatch):
    app, service, client, case_id, enrollment = feature_app
    # Classic little-endian PCAP header, no packets; a valid empty capture.
    raw = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    response = client.post("/api/v1/pcaps", files={"file": ("capture.pcap", raw, "application/octet-stream")}, data={"case_id": case_id})
    assert response.status_code == 202, response.text
    result = response.json()
    assert client.get("/api/v1/artifacts/" + result["artifact_id"] + "/download").content == raw
    from cbb.integrations import process_pcap
    monkeypatch.setenv("CBB_SURICATA_EXECUTABLE", "missing-suricata-tool")
    with service.db.read() as c:
        job = row(c, select(D.jobs).where(D.jobs.c.id == result["job_id"]))
    with pytest.raises(DomainError, match="PCAP is preserved"):
        process_pcap(service, json.loads(job["payload"]))
    assert client.get("/api/v1/artifacts/" + result["artifact_id"] + "/download").content == raw


def baseline(service, enrollment, monkeypatch):
    with service.db.read() as c:
        col = row(c, select(D.collectors).where(D.collectors.c.id == enrollment["collector_id"]))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    sequence = 0
    for bucket in range(40):
        stamp = (start + timedelta(minutes=5 * bucket)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        monkeypatch.setattr("cbb.service.now", lambda value=stamp: value)
        events = []
        for _ in range(2 + bucket % 5):
            sequence += 1
            raw = canon({"process": "benign.exe", "event_type": "process.create", "severity": 1})
            events.append({"boot_id": "baseline", "source_seq": str(sequence), "source_type": "lab.fixture", "event_type": "process.create", "collected_at": stamp, "original_timestamp": stamp, "raw_base64": base64.b64encode(raw).decode(), "raw_sha256": sha(raw)})
        service.accept(col, events)
    service.seal_pending(1000)
    return {"confirm_benign": True, "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T03:20:00Z"}, col


def test_real_model_holdout_reproducibility_and_guardrails(feature_app, monkeypatch):
    app, service, client, case_id, enrollment = feature_app
    payload, col = baseline(service, enrollment, monkeypatch)
    trained = train(service, payload)
    manifest = trained["manifest"]
    assert manifest["training_windows"] + manifest["holdout_windows"] == 40
    assert manifest["train_last_window"] < manifest["holdout_first_window"]
    assert not set(manifest["training_evidence_ids"]) & set(manifest["holdout_evidence_ids"])
    assert 0 <= manifest["evaluation"]["false_positive_rate"] <= 1
    assert manifest["evaluation"]["attack_recall"] is None
    assert train(service, payload)["duplicate"]
    with pytest.raises(DomainError, match="avoid evaluation leakage"):
        score(service, {"model_id": trained["model_id"], "start": payload["start"], "end": payload["end"]})
    empty = score(service, {"model_id": trained["model_id"], "start": payload["end"], "end": "2026-01-02T00:00:00Z"})
    assert empty["windows_scored"] == 0
    model_path = service.root / "models" / (trained["model_id"] + ".joblib")
    model_path.write_bytes(b"changed untrusted serialized payload")
    with pytest.raises(DomainError, match="registered version"):
        score(service, {"model_id": trained["model_id"]})


def test_model_requires_review_and_sufficient_data(feature_app):
    _, service, _, _, _ = feature_app
    with pytest.raises(DomainError, match="reviewer must confirm"):
        train(service, {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"})
    with pytest.raises(DomainError, match="At least 30"):
        train(service, {"confirm_benign": True, "start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"})
