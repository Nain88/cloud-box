import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def uid(): return str(uuid.uuid4())
def now(): return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
def sha(data): return hashlib.sha256(data).hexdigest()
def file_sha(path):
    digest=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):digest.update(chunk)
    return digest.hexdigest()
def canon(value): return rfc8785.dumps(value)
def dumps(value): return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
def loads(value, default=None): return json.loads(value) if value else default
def strict_json(data):
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj: raise ValueError("Duplicate JSON key")
            obj[k] = v
        return obj
    def invalid(v): raise ValueError("Non-finite JSON value")
    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    except RecursionError as ex:
        raise ValueError("JSON nesting exceeds limit") from ex
    def depth(v, level=0):
        if level > 20: raise ValueError("JSON nesting exceeds 20 levels")
        if isinstance(v, dict):
            for child in v.values(): depth(child, level+1)
        elif isinstance(v, list):
            for child in v: depth(child, level+1)
    depth(value)
    return value

def chain_hash(previous, sequence, envelope):
    return sha(b"CBB-RECORD-v1\0" + bytes.fromhex(previous) + sequence.to_bytes(8,"big") + bytes.fromhex(sha(envelope)))

def atomic_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uid() + ".tmp")
    with temp.open("xb") as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(temp, path)
    if os.name != "nt":
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)

def keypair(path):
    path = Path(path)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), None)
    else:
        key = Ed25519PrivateKey.generate()
        atomic_write(path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        if os.name != "nt": path.chmod(0o600)
    return key

def public_b64(key):
    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

def sign(key, domain, payload):
    return {"payload": payload, "signature": base64.b64encode(key.sign(domain.encode()+b"\0"+canon(payload))).decode(), "public_key": public_b64(key)}

def verify_signature(document, domain, trusted_key):
    if document.get("public_key") != trusted_key: raise ValueError("Signing key differs from pinned key")
    Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted_key, validate=True)).verify(base64.b64decode(document["signature"], validate=True), domain.encode()+b"\0"+canon(document["payload"]))
    return document["payload"]

