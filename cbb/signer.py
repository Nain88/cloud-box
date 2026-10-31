"""Separate, authenticated signing service. Keep its key off the application host.

The signer prevents checkpoint/configuration rollback and conflicting re-signing.
It does not decide whether source observations or analyst conclusions are true.
"""
import argparse
import json
import os
import secrets
import sqlite3
import threading
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from .crypto import canon, keypair, public_b64, sha, sign

DOMAINS = {"CBB-CHECKPOINT-v1", "CBB-CONFIG-v1", "CBB-EXPORT-v1", "CBB-ACQUISITION-v1", "CBB-JOB-v1"}


def create_signer(data=None, token=None):
    root = Path(data or os.getenv("CBB_SIGNER_DATA", "signer-data")).resolve()
    secret = token if token is not None else os.getenv("CBB_SIGNER_TOKEN", "")
    if len(secret) < 32:
        raise ValueError("CBB_SIGNER_TOKEN must contain at least 32 random characters")
    root.mkdir(parents=True, exist_ok=True)
    key = keypair(root / "signing.pem")
    lock = threading.RLock()
    db = sqlite3.connect(root / "state.sqlite3", check_same_thread=False, timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS state (scope TEXT PRIMARY KEY, version INTEGER NOT NULL, digest TEXT NOT NULL, document TEXT NOT NULL)")
    db.commit()
    app = FastAPI(title="Cyber Black Box isolated signer", docs_url=None, redoc_url=None)
    app.state.key = key

    def authenticated(value):
        if not secrets.compare_digest(value or "", "Bearer " + secret):
            raise HTTPException(401, "Signer authentication required")

    @app.get("/public-key")
    def public_key(authorization: str = Header(default="")):
        authenticated(authorization)
        return {"public_key": public_b64(key), "algorithm": "Ed25519"}

    @app.get("/health/live")
    def live():
        return {"status": "alive"}

    @app.post("/sign")
    async def signing(request: Request, authorization: str = Header(default="")):
        authenticated(authorization)
        from .crypto import strict_json
        body_bytes = bytearray()
        async for chunk in request.stream():
            body_bytes.extend(chunk)
            if len(body_bytes) > 8 * 1024 * 1024:
                raise HTTPException(413, "Signing request exceeds 8 MiB")
        try:
            body = strict_json(body_bytes)
            domain, payload = body["domain"], body["payload"]
            if domain not in DOMAINS or not isinstance(payload, dict):
                raise ValueError("Unsupported signing domain or payload")
            encoded = canon(payload)
        except (ValueError, KeyError, TypeError) as ex:
            raise HTTPException(422, str(ex)) from ex
        scope = None
        version = None
        try:
            if domain == "CBB-CHECKPOINT-v1":
                scope = "checkpoint:" + str(payload["deployment_id"])
                version = int(payload["checkpoint_seq"])
                if version < 1 or len(payload["previous_checkpoint_sha256"]) != 64:
                    raise ValueError("Invalid checkpoint sequence or previous digest")
            elif domain == "CBB-CONFIG-v1":
                scope = "config:" + str(payload["collector_id"])
                version = int(payload["version"])
                if version < 1:
                    raise ValueError("Invalid configuration version")
        except (KeyError, ValueError, TypeError) as ex:
            raise HTTPException(422, str(ex)) from ex
        with lock:
            try:
                db.execute("BEGIN IMMEDIATE")
                if scope:
                    previous = db.execute("SELECT version,digest,document FROM state WHERE scope=?", (scope,)).fetchone()
                    digest = sha(encoded)
                    if previous and version == previous[0] and digest == previous[1]:
                        db.rollback()
                        return json.loads(previous[2])
                    if previous and version <= previous[0]:
                        raise HTTPException(409, "Refusing rollback or a conflicting payload at an existing version")
                    if domain == "CBB-CHECKPOINT-v1":
                        expected_version = previous[0] + 1 if previous else 1
                        expected_digest = sha(canon(json.loads(previous[2]))) if previous else "0" * 64
                        if version != expected_version or payload["previous_checkpoint_sha256"] != expected_digest:
                            raise HTTPException(409, "Checkpoint must extend the signer's recorded chain")
                    document = sign(key, domain, payload)
                    db.execute("INSERT INTO state(scope,version,digest,document) VALUES(?,?,?,?) ON CONFLICT(scope) DO UPDATE SET version=excluded.version,digest=excluded.digest,document=excluded.document", (scope, version, digest, canon(document).decode()))
                else:
                    document = sign(key, domain, payload)
                db.commit()
                return document
            except Exception:
                db.rollback()
                raise

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default=os.getenv("CBB_SIGNER_DATA", "signer-data"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(create_signer(args.data), host=args.host, port=args.port, workers=1)


if __name__ == "__main__":
    main()
