import base64
import json
import time
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from cbb.agent import Agent, Spool, SpoolFull, secure_client
from cbb.crypto import canon, keypair, public_b64, sha, sign, verify_signature
from cbb.signer import create_signer
from cbb.witness import create_witness


def checkpoint(sequence=1, previous="0" * 64, head="a" * 64):
    return {"checkpoint_version": "1.0", "checkpoint_id": "cp-" + str(sequence), "checkpoint_seq": str(sequence), "deployment_id": "deployment", "created_at": "2026-10-29T00:00:00Z", "previous_checkpoint_sha256": previous, "chains": [{"id": "chain", "purpose": "evidence", "sequence": str(sequence), "head_hash": head, "genesis": "b" * 64}], "segments": []}


def test_signer_requires_secret_and_refuses_fork_and_rollback(tmp_path):
    with pytest.raises(ValueError):
        create_signer(tmp_path / "invalid", "short")
    app = create_signer(tmp_path / "signer", "x" * 32)
    with TestClient(app) as client:
        assert client.get("/public-key").status_code == 401
        headers = {"Authorization": "Bearer " + "x" * 32}
        key = client.get("/public-key", headers=headers).json()["public_key"]
        body = {"domain": "CBB-CHECKPOINT-v1", "payload": checkpoint()}
        first = client.post("/sign", json=body, headers=headers)
        assert first.status_code == 200
        assert verify_signature(first.json(), body["domain"], key) == body["payload"]
        assert client.post("/sign", json=body, headers=headers).json() == first.json()
        body["payload"]["checkpoint_id"] = "fork"
        assert client.post("/sign", json=body, headers=headers).status_code == 409
        second = {"domain": body["domain"], "payload": checkpoint(2, sha(canon(first.json())))}
        assert client.post("/sign", json=second, headers=headers).status_code == 200
        assert client.post("/sign", json={"domain": body["domain"], "payload": checkpoint()}, headers=headers).status_code == 409
        assert client.post("/sign", json={"domain": "arbitrary", "payload": {}}, headers=headers).status_code == 422


def test_signer_configuration_versions_are_monotonic(tmp_path):
    with TestClient(create_signer(tmp_path, "a" * 32)) as client:
        headers = {"Authorization": "Bearer " + "a" * 32}
        body = {"domain": "CBB-CONFIG-v1", "payload": {"collector_id": "c", "version": 1, "configuration": {"paths": []}}}
        assert client.post("/sign", json=body, headers=headers).status_code == 200
        body["payload"]["configuration"]["paths"] = ["changed"]
        assert client.post("/sign", json=body, headers=headers).status_code == 409
        body["payload"]["version"] = 2
        assert client.post("/sign", json=body, headers=headers).status_code == 200


def test_witness_pins_keys_refuses_forks_gaps_and_chain_rollback(tmp_path):
    server_key = keypair(tmp_path / "server.pem")
    unrelated_key = keypair(tmp_path / "other.pem")
    with TestClient(create_witness(tmp_path / "witness", public_b64(server_key))) as client:
        trusted_witness = client.get("/public-key").json()["public_key"]
        first = sign(server_key, "CBB-CHECKPOINT-v1", checkpoint())
        response = client.post("/checkpoints", json=first)
        assert response.status_code == 200
        receipt = verify_signature(response.json(), "CBB-WITNESS-v1", trusted_witness)
        assert receipt["checkpoint_sha256"] == sha(canon(first))
        assert client.post("/checkpoints", json=first).json() == response.json()
        assert client.post("/checkpoints", json=sign(unrelated_key, "CBB-CHECKPOINT-v1", checkpoint())).status_code == 422
        fork = checkpoint(head="c" * 64)
        assert client.post("/checkpoints", json=sign(server_key, "CBB-CHECKPOINT-v1", fork)).status_code == 409
        assert client.post("/checkpoints", json=sign(server_key, "CBB-CHECKPOINT-v1", checkpoint(3, sha(canon(first))))).status_code == 409
        second = checkpoint(2, sha(canon(first)))
        second["chains"][0]["sequence"] = "0"
        assert client.post("/checkpoints", json=sign(server_key, "CBB-CHECKPOINT-v1", second)).status_code == 409
        second["chains"][0]["sequence"] = "2"
        assert client.post("/checkpoints", json=sign(server_key, "CBB-CHECKPOINT-v1", second)).status_code == 200
        assert client.get("/checkpoints/deployment/latest").json()["checkpoint"]["payload"]["checkpoint_seq"] == "2"


def test_spool_preserves_bytes_cursor_and_sequence_across_restart(tmp_path):
    spool = Spool(tmp_path)
    original = b'{"a": 1}\r\n'
    spool.enqueue(original, "suricata.eve", "network.event", cursor={"offset": 10}, cursor_key="file")
    first = json.loads(spool.batch()[0]["body"])
    assert base64.b64decode(first["raw_base64"]) == original
    assert spool.get("file") == {"offset": 10}
    spool.close()
    spool = Spool(tmp_path)
    assert json.loads(spool.batch()[0]["body"]) == first
    spool.enqueue(b"{}", "collector.health", "health")
    assert json.loads(spool.batch()[1]["body"])["source_seq"] == "2"
    spool.max_bytes = 1
    with pytest.raises(SpoolFull):
        spool.enqueue(b"{}", "collector.health", "health", cursor={"offset": 20}, cursor_key="file")
    assert spool.get("file")["offset"] == 10
    assert spool.get("sequence") == 2
    spool.close()


def config_for(root, key=None):
    return {"server": "http://127.0.0.1:8765", "collector_id": "c", "token": "t", "server_signing_key": public_b64(key) if key else "", "data": str(root / "agent"), "allowed_paths": [str(root / "watched")], "enable_acquisitions": True}


def test_agent_keeps_raw_until_receipt_is_sealed(tmp_path):
    state = {"sealed": False}

    def transport(request):
        if request.url.path == "/api/v1/ingest/events":
            assert json.loads(request.content)["events"][0]["raw_sha256"] == sha(b"{}")
            return httpx.Response(202, json={"items": [{"source_seq": "1", "outcome": "accepted", "receipt_id": "r", "evidence_id": "e", "preservation_state": "STAGED"}]})
        return httpx.Response(200, json={"id": "r", "state": "SEALED" if state["sealed"] else "STAGED", "evidence_id": "e"})

    client = httpx.Client(base_url="http://127.0.0.1:8765", transport=httpx.MockTransport(transport))
    agent = Agent(config_for(tmp_path), client=client)
    try:
        agent.spool.enqueue(b"{}", "collector.health", "health")
        agent.flush()
        assert agent.spool.status()["awaiting_seal"] == 1
        state["sealed"] = True
        agent.flush()
        assert agent.spool.status()["bytes"] == 0
    finally:
        agent.close()


def test_agent_rejects_remote_http_and_untrusted_config(tmp_path):
    with pytest.raises(ValueError):
        secure_client({"server": "http://example.com", "token": "t"})
    key = keypair(tmp_path / "key.pem")
    configuration = {"paths": [str(tmp_path / "outside")], "channels": [], "poll_seconds": 5, "max_file_bytes": 20971520}
    signed = sign(key, "CBB-CONFIG-v1", {"collector_id": "c", "version": 1, "configuration": configuration})
    client = httpx.Client(base_url="http://127.0.0.1", transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"signed_configuration": signed})))
    agent = Agent(config_for(tmp_path, key), client=client)
    try:
        with pytest.raises(ValueError, match="allowlist"):
            agent.heartbeat()
        assert agent.config_version == 0
    finally:
        agent.close()


def test_fim_and_yara_reconcile_actual_local_files(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    file = watched / "sample.txt"
    file.write_bytes(b"clean")
    rules = tmp_path / "rules.yar"
    rules.write_text('rule test_marker { strings: $a = "CBB_TEST_MARKER" condition: $a }')
    config = config_for(tmp_path)
    config["yara_rules"] = str(rules)
    agent = Agent(config, client=httpx.Client())
    try:
        agent.configuration["paths"] = [str(watched)]
        agent.reconcile_files()
        file.write_bytes(b"CBB_TEST_MARKER")
        agent.reconcile_files()
        types = [json.loads(r["body"])["source_type"] for r in agent.spool.batch()]
        assert types == ["fim", "fim", "yara"]
        file.unlink()
        agent.reconcile_files()
        assert json.loads(agent.spool.batch()[-1]["body"])["event_type"] == "file.delete"
    finally:
        agent.close()


def test_file_acquisition_enforces_paths_and_preserves_bytes(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "sample.bin").write_bytes(b"\x00\x01evidence\xff")
    agent = Agent(config_for(tmp_path), client=httpx.Client())
    try:
        agent.configuration["paths"] = [str(watched)]
        target = tmp_path / "capture.zip"
        agent.collect_files([str(watched / "sample.bin")], target, 100000, time.monotonic() + 5)
        with zipfile.ZipFile(target) as archive:
            manifest = json.loads(archive.read("acquisition-manifest.json"))
            entry = manifest["files"][0]
            raw = archive.read(entry["member"])
            assert raw == b"\x00\x01evidence\xff"
            assert sha(raw) == entry["sha256"]
        with pytest.raises(ValueError, match="allowlist"):
            agent.collect_files([str(tmp_path / "outside")], tmp_path / "bad.zip", 100000, time.monotonic() + 5)
    finally:
        agent.close()


def test_tail_resume_keeps_original_newlines(tmp_path):
    file = tmp_path / "eve.json"
    line1 = b'{"event_type":"flow"}\r\n'
    line2 = b'{"event_type":"alert"}\n'
    file.write_bytes(line1 + line2)
    agent = Agent(config_for(tmp_path), client=httpx.Client())
    try:
        agent.tail_log(file, "suricata.eve")
        agent.tail_log(file, "suricata.eve")
        events = [json.loads(r["body"]) for r in agent.spool.batch()]
        assert len(events) == 2
        assert [base64.b64decode(e["raw_base64"]) for e in events] == [line1, line2]
    finally:
        agent.close()
