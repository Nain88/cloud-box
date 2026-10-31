"""Independent checkpoint witness with persistent fork and rollback detection.

Pin the deployment signing key out of band. A witness on the application host
is useful for development but is not an independent integrity anchor.
"""
import argparse
import json
import os
import sqlite3
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from .crypto import canon, keypair, now, public_b64, sha, sign, strict_json, uid, verify_signature


def create_witness(data=None, trusted_key=None, deployment_id=None):
    root = Path(data or os.getenv("CBB_WITNESS_DATA", "witness-data")).resolve()
    pinned_key = trusted_key or os.getenv("CBB_WITNESS_TRUSTED_KEY", "")
    pinned_deployment = deployment_id or os.getenv("CBB_WITNESS_DEPLOYMENT_ID", "")
    if not pinned_key:
        raise ValueError("Configure the independently verified deployment signing key with CBB_WITNESS_TRUSTED_KEY")
    root.mkdir(parents=True, exist_ok=True)
    key = keypair(root / "witness.pem")
    db = sqlite3.connect(root / "witness.sqlite3", check_same_thread=False, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS checkpoints (deployment TEXT NOT NULL, sequence INTEGER NOT NULL, digest TEXT NOT NULL, document TEXT NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY(deployment,sequence))")
    db.commit()
    lock = threading.RLock()
    app = FastAPI(title="Cyber Black Box checkpoint witness", docs_url=None, redoc_url=None)

    @app.get("/public-key")
    def public_key():
        return {"public_key": public_b64(key), "algorithm": "Ed25519"}

    @app.get("/health/live")
    def live():
        return {"status": "alive"}

    @app.get("/checkpoints/{deployment}/latest")
    def latest(deployment: str):
        with lock:
            previous = db.execute("SELECT document,receipt FROM checkpoints WHERE deployment=? ORDER BY sequence DESC LIMIT 1", (deployment,)).fetchone()
        if not previous:
            raise HTTPException(404, "No witnessed checkpoint for this deployment")
        return {"checkpoint": json.loads(previous["document"]), "receipt": json.loads(previous["receipt"])}

    @app.post("/checkpoints")
    async def checkpoint(request: Request):
        body_bytes = bytearray()
        async for chunk in request.stream():
            body_bytes.extend(chunk)
            if len(body_bytes) > 8 * 1024 * 1024:
                raise HTTPException(413, "Checkpoint exceeds 8 MiB")
        try:
            document = strict_json(body_bytes)
            payload = verify_signature(document, "CBB-CHECKPOINT-v1", pinned_key)
            deployment = payload["deployment_id"]
            sequence = int(payload["checkpoint_seq"])
            if not isinstance(deployment, str) or not deployment or len(deployment) > 100 or sequence < 1:
                raise ValueError("Invalid deployment or sequence")
            if pinned_deployment and deployment != pinned_deployment:
                raise ValueError("Unexpected deployment identifier")
            encoded = canon(document)
            digest = sha(encoded)
        except Exception as ex:
            raise HTTPException(422, "Invalid checkpoint or untrusted signing key") from ex
        with lock:
            try:
                db.execute("BEGIN IMMEDIATE")
                duplicate = db.execute("SELECT digest,receipt FROM checkpoints WHERE deployment=? AND sequence=?", (deployment, sequence)).fetchone()
                if duplicate:
                    if duplicate["digest"] != digest:
                        raise HTTPException(409, "Checkpoint fork detected: sequence already witnessed with a different digest")
                    db.rollback()
                    return json.loads(duplicate["receipt"])
                previous = db.execute("SELECT sequence,digest,document FROM checkpoints WHERE deployment=? ORDER BY sequence DESC LIMIT 1", (deployment,)).fetchone()
                expected_sequence = previous["sequence"] + 1 if previous else 1
                expected_digest = previous["digest"] if previous else "0" * 64
                if sequence != expected_sequence or payload.get("previous_checkpoint_sha256") != expected_digest:
                    raise HTTPException(409, "Checkpoint must extend the witness history without gaps or rollback")
                if previous:
                    previous_chains = {c["id"]: c for c in json.loads(previous["document"])["payload"]["chains"]}
                    current_chains = {c["id"]: c for c in payload["chains"]}
                    for chain_id, old in previous_chains.items():
                        current = current_chains.get(chain_id)
                        if not current or current["genesis"] != old["genesis"] or int(current["sequence"]) < int(old["sequence"]):
                            raise HTTPException(409, "Checkpoint chain disappeared, changed genesis, or rolled back")
                        if current["sequence"] == old["sequence"] and current["head_hash"] != old["head_hash"]:
                            raise HTTPException(409, "Checkpoint changed a chain head without extending it")
                receipt = sign(key, "CBB-WITNESS-v1", {"receipt_version": "1.0", "receipt_id": uid(), "deployment_id": deployment, "checkpoint_id": payload["checkpoint_id"], "checkpoint_seq": str(sequence), "checkpoint_sha256": digest, "received_at": now(), "previous_checkpoint_sha256": expected_digest})
                db.execute("INSERT INTO checkpoints VALUES(?,?,?,?,?)", (deployment, sequence, digest, encoded.decode(), canon(receipt).decode()))
                db.commit()
                return receipt
            except Exception:
                db.rollback()
                raise

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default=os.getenv("CBB_WITNESS_DATA", "witness-data"))
    parser.add_argument("--trusted-key", default=os.getenv("CBB_WITNESS_TRUSTED_KEY", ""))
    parser.add_argument("--deployment-id", default=os.getenv("CBB_WITNESS_DEPLOYMENT_ID", ""))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8767)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(create_witness(args.data, args.trusted_key, args.deployment_id), host=args.host, port=args.port, workers=1)


if __name__ == "__main__":
    main()
