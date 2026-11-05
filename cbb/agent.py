"""Durable Windows/Linux collector for explicitly configured local sources.

No source is enabled merely by installing the agent. Enrollment pins the server
signing key; local allowlists restrict remotely signed collection settings.
"""
import argparse
import base64
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import queue
import random
import selectors
import shutil
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import psutil

from .crypto import atomic_write, canon, dumps, now, sha, uid, verify_signature

log = logging.getLogger("cbb.agent")
MAX_EVENT = 65536


class SpoolFull(RuntimeError):
    pass


class Spool:
    """Source cursor and queued event commit together, before any network send."""

    def __init__(self, root, max_bytes=512 * 1024 * 1024):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.root / "spool.sqlite3", timeout=30, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,body TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'QUEUED',receipt TEXT,evidence TEXT,error TEXT,created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY,digest TEXT,size INTEGER,mtime INTEGER);
            CREATE TABLE IF NOT EXISTS acquisitions (id TEXT PRIMARY KEY,state TEXT NOT NULL,artifact TEXT,upload_id TEXT,error TEXT,updated_at TEXT NOT NULL);
        """)
        self.db.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS spool_usage (id INTEGER PRIMARY KEY CHECK(id=1), bytes INTEGER NOT NULL);
            INSERT OR REPLACE INTO spool_usage SELECT 1, COALESCE(SUM(LENGTH(CAST(body AS BLOB))),0) FROM events;
            CREATE TRIGGER IF NOT EXISTS spool_usage_insert AFTER INSERT ON events BEGIN
                UPDATE spool_usage SET bytes=bytes+LENGTH(CAST(NEW.body AS BLOB)) WHERE id=1;
            END;
            CREATE TRIGGER IF NOT EXISTS spool_usage_delete AFTER DELETE ON events BEGIN
                UPDATE spool_usage SET bytes=bytes-LENGTH(CAST(OLD.body AS BLOB)) WHERE id=1;
            END;
            COMMIT;
        """)
        self.db.commit()
        boot_signature = sha(str(int(psutil.boot_time())).encode())[:32]
        self.boot_id = self.get("boot_signature")
        if self.boot_id != boot_signature:
            self.set("boot_signature", boot_signature)
            self.boot_id = boot_signature

    def get(self, key, default=None):
        with self.lock:
            item = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(item[0]) if item else default

    def set(self, key, value):
        with self.lock, self.db:
            self.db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, dumps(value)))

    def enqueue(self, raw, source_type, event_type, media_type="application/json", original_timestamp=None, cursor=None, cursor_key=None):
        if len(raw) > MAX_EVENT:
            raise ValueError("Source event exceeds 64 KiB; cursor was not advanced")
        with self.lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                used = self.db.execute("SELECT bytes FROM spool_usage WHERE id=1").fetchone()[0]
                if used + len(raw) * 2 + 2048 > self.max_bytes or shutil.disk_usage(self.root).free < 50 * 1024 * 1024:
                    raise SpoolFull("Spool capacity reached; collection paused without advancing source cursors")
                old = self.db.execute("SELECT value FROM meta WHERE key='sequence'").fetchone()
                sequence = int(old[0]) + 1 if old else 1
                event = {"schema_version": "cbb.ingest/1.0", "boot_id": self.boot_id, "source_seq": str(sequence), "source_type": source_type, "event_type": event_type, "collected_at": now(), "original_timestamp": original_timestamp, "raw_media_type": media_type, "raw_base64": base64.b64encode(raw).decode(), "raw_sha256": sha(raw), "source_cursor": cursor or {}}
                result = self.db.execute("INSERT INTO events(body,created_at) VALUES(?,?)", (canon(event).decode(), now()))
                self.db.execute("INSERT INTO meta VALUES('sequence',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(sequence),))
                if cursor_key:
                    self.db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (cursor_key, dumps(cursor)))
                self.db.commit()
                return result.lastrowid
            except Exception:
                self.db.rollback()
                raise

    def batch(self):
        result = []
        size = 0
        with self.lock:
            for row in self.db.execute("SELECT * FROM events WHERE state='QUEUED' ORDER BY id LIMIT 100"):
                if size + len(row["body"].encode()) > 900000:
                    break
                result.append(dict(row))
                size += len(row["body"].encode())
        return result

    def status(self):
        with self.lock:
            counts = dict(self.db.execute("SELECT state,COUNT(*) FROM events GROUP BY state").fetchall())
            used = self.db.execute("SELECT bytes FROM spool_usage WHERE id=1").fetchone()[0]
        allocated = sum(path.stat().st_size for path in self.root.glob("spool.sqlite3*") if path.exists())
        return {"allocated_bytes": allocated, "queued": counts.get("QUEUED", 0), "awaiting_seal": counts.get("STAGED", 0), "quarantined": counts.get("QUARANTINED", 0), "blocked": counts.get("BLOCKED", 0), "bytes": used, "max_bytes": self.max_bytes}

    def close(self):
        self.db.close()


def secure_client(config, *, enrollment=False):
    address = urlparse(config["server"])
    if address.username or address.password or address.query or address.fragment or address.path not in ("", "/"):
        raise ValueError("Server must be a base URL without credentials, query or path")
    if address.scheme != "https" and not (address.scheme == "http" and address.hostname in ("127.0.0.1", "localhost", "::1")):
        raise ValueError("Remote servers require HTTPS; insecure transport is allowed only on loopback")
    context = ssl.create_default_context(cafile=config.get("ca_file") or None)
    if config.get("cert_file"):
        context.load_cert_chain(config["cert_file"], config.get("key_file"))
    headers = {} if enrollment else {"Authorization": "Bearer " + config["token"]}
    return httpx.Client(base_url=config["server"].rstrip("/"), verify=context, headers=headers, timeout=httpx.Timeout(30, connect=10), follow_redirects=False)


def file_hash(path, limit=None):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if limit is not None and size > limit:
                raise ValueError("File exceeds the configured byte limit")
            digest.update(chunk)
    return digest.hexdigest(), size


def inside(path, roots):
    resolved = Path(path).resolve()
    return any(resolved == root or resolved.is_relative_to(root) for root in roots)


class Agent:
    def __init__(self, config, root=None, client=None):
        self.config = config
        self.root = Path(root or config.get("data", "agent-data")).resolve()
        self.spool = Spool(self.root, int(config.get("spool_bytes", 512 * 1024 * 1024)))
        self.client = client or secure_client(config)
        self.local_roots = [Path(p).resolve() for p in config.get("allowed_paths", [])]
        self.errors = {}
        self.configuration = self.spool.get("configuration", {"paths": [], "channels": [], "poll_seconds": 5, "max_file_bytes": 20971520})
        self.config_version = self.spool.get("config_version", 0)
        self.changed = queue.Queue(maxsize=10000)
        self.observer = None
        self.rules = None
        if config.get("yara_rules"):
            import yara
            self.rules = yara.compile(filepath=str(Path(config["yara_rules"]).resolve()))
        with self.spool.lock, self.spool.db:
            self.spool.db.execute("UPDATE acquisitions SET state='INTERRUPTED',error='Agent restarted; acquisition must be reviewed, not replayed',updated_at=? WHERE state='RUNNING'", (now(),))
        self.start_watchdog()

    def health(self):
        from .sensor_health import input_health
        memory = self.memory_available()
        return {"version": "0.1.0", "platform": sys.platform, "time": now(), "config_version": self.config_version, "spool": self.spool.status(), "errors": self.errors, "capabilities": {"windows_events": os.name == "nt" and bool(self.config.get("enable_events")), "linux_journal": sys.platform.startswith("linux") and bool(self.config.get("enable_events")), "fim": bool(self.local_roots), "yara": bool(self.rules), "memory_capture": memory, "acquisitions": bool(self.config.get("enable_acquisitions", False))}, "disk_free": shutil.disk_usage(self.root).free, "firewall_inputs": input_health(self.config.get("firewall_files", [])), "network_inputs": input_health(self.config.get("eve_files", [])), "zeek_inputs": input_health(self.config.get("zeek_files", []))}

    def heartbeat(self):
        response = self.client.post("/api/v1/collectors/heartbeat", json=self.health())
        response.raise_for_status()
        signed = response.json()["signed_configuration"]
        payload = verify_signature(signed, "CBB-CONFIG-v1", self.config["server_signing_key"])
        if payload["collector_id"] != self.config["collector_id"]:
            raise ValueError("Configuration was signed for another collector")
        version = int(payload["version"])
        if version < self.config_version:
            raise ValueError("Configuration rollback rejected")
        if version == self.config_version and self.config_version and canon(payload["configuration"]) != canon(self.configuration):
            raise ValueError("Conflicting configuration at the same version")
        if version != self.config_version:
            configuration = payload["configuration"]
            if not isinstance(configuration.get("paths", []), list) or len(configuration.get("paths", [])) > 50:
                raise ValueError("Invalid signed path configuration")
            rejected = [p for p in configuration.get("paths", []) if not inside(p, self.local_roots)]
            if rejected:
                raise ValueError("Signed paths exceed the local allowlist; update local agent policy before applying")
            channels = configuration.get("channels", [])
            allowed_channels = self.config.get("allowed_channels", ["System", "Application", "Security", "Microsoft-Windows-Sysmon/Operational"])
            if any(c not in allowed_channels for c in channels):
                raise ValueError("Signed event channel exceeds the local channel allowlist")
            self.spool.set("configuration", configuration)
            self.spool.set("config_version", version)
            self.configuration, self.config_version = configuration, version
            self.start_watchdog()
        self.errors.pop("heartbeat", None)

    def flush(self):
        batch = self.spool.batch()
        if batch:
            response = self.client.post("/api/v1/ingest/events", json={"batch_id": uid(), "events": [json.loads(r["body"]) for r in batch]})
            response.raise_for_status()
            by_sequence = {json.loads(r["body"])["source_seq"]: r["id"] for r in batch}
            with self.spool.lock, self.spool.db:
                for item in response.json()["items"]:
                    identity = by_sequence.get(item["source_seq"])
                    if identity is None:
                        raise ValueError("Server receipt references an unsubmitted sequence")
                    if item["outcome"] in ("accepted", "duplicate"):
                        state = item["preservation_state"]
                        if state == "SEALED":
                            self.spool.db.execute("DELETE FROM events WHERE id=?", (identity,))
                        else:
                            self.spool.db.execute("UPDATE events SET state=?,receipt=?,evidence=? WHERE id=?", (state, item["receipt_id"], item["evidence_id"], identity))
                    else:
                        self.spool.db.execute("UPDATE events SET state='BLOCKED',error=? WHERE id=?", (dumps(item)[:2000], identity))
        with self.spool.lock:
            pending = [dict(r) for r in self.spool.db.execute("SELECT id,receipt FROM events WHERE state IN ('STAGED','QUARANTINED') ORDER BY id LIMIT 50")]
        for item in pending:
            response = self.client.get("/api/v1/receipts/" + item["receipt"])
            response.raise_for_status()
            receipt = response.json()
            with self.spool.lock, self.spool.db:
                if receipt["state"] == "SEALED":
                    self.spool.db.execute("DELETE FROM events WHERE id=?", (item["id"],))
                elif receipt["state"] == "QUARANTINED":
                    self.spool.db.execute("UPDATE events SET state='QUARANTINED',error=? WHERE id=?", (receipt.get("error"), item["id"]))

    def start_watchdog(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
        paths = [Path(p).resolve() for p in self.configuration.get("paths", []) if inside(p, self.local_roots)]
        if not paths:
            return
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
        agent = self

        class Changes(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.is_directory or event.event_type not in ("created", "modified", "deleted", "moved"):
                    return
                for path in (event.src_path, getattr(event, "dest_path", "")):
                    if path:
                        try:
                            agent.changed.put_nowait(path)
                        except queue.Full:
                            agent.errors["watchdog"] = "Event queue overflow; reconciliation will recover current file state, not every intermediate change"

        observer = Observer()
        for path in paths:
            watch = path if path.is_dir() else path.parent
            if watch.exists():
                observer.schedule(Changes(), str(watch), recursive=path.is_dir())
        observer.start()
        self.observer = observer

    def current_roots(self):
        return [Path(p).resolve() for p in self.configuration.get("paths", []) if inside(p, self.local_roots)]

    def inspect_file(self, candidate):
        path = Path(candidate)
        roots = self.current_roots()
        if path.is_symlink() or not inside(path, roots) or inside(path, [self.root]):
            return
        path = path.resolve()
        if path.exists() and not path.is_file():
            return
        with self.spool.lock:
            previous = self.spool.db.execute("SELECT digest,size,mtime FROM files WHERE path=?", (str(path),)).fetchone()
        if not path.exists():
            if previous:
                raw = canon({"path": str(path), "action": "deleted", "previous_sha256": previous["digest"], "severity": 3, "summary": "Watched file deleted"})
                self.spool.enqueue(raw, "fim", "file.delete", original_timestamp=now())
                with self.spool.lock, self.spool.db:
                    self.spool.db.execute("DELETE FROM files WHERE path=?", (str(path),))
            return
        before = path.stat()
        if before.st_size > min(int(self.configuration.get("max_file_bytes", 20971520)), 20971520):
            self.errors["fim.limit"] = "Some watched files exceed the file-size limit; those bytes are not scanned"
            return
        digest, size = file_hash(path, 20971520)
        after = path.stat()
        if before.st_mtime_ns != after.st_mtime_ns or before.st_size != after.st_size:
            self.errors["fim.race"] = "A file changed while hashing; retrying on the next reconciliation"
            return
        if previous and previous["digest"] == digest:
            return
        action = "modified" if previous else "baseline"
        raw = canon({"path": str(path), "action": action, "sha256": digest, "previous_sha256": previous["digest"] if previous else None, "size": size, "severity": 3 if previous else 0, "summary": "Watched file " + action})
        self.spool.enqueue(raw, "fim", "file." + action, original_timestamp=now())
        if self.rules:
            matches = self.rules.match(filepath=str(path), timeout=3)
            if matches:
                data = {"path": str(path), "sha256": digest, "rules": [{"name": m.rule, "namespace": m.namespace, "tags": m.tags} for m in matches], "severity": 4, "summary": "YARA match: " + ", ".join(m.rule for m in matches)[:200], "rule_sha256": file_hash(self.config["yara_rules"])[0]}
                self.spool.enqueue(canon(data), "yara", "file.yara_match", original_timestamp=now())
        with self.spool.lock, self.spool.db:
            self.spool.db.execute("INSERT INTO files VALUES(?,?,?,?) ON CONFLICT(path) DO UPDATE SET digest=excluded.digest,size=excluded.size,mtime=excluded.mtime", (str(path), digest, size, after.st_mtime_ns))

    def reconcile_files(self):
        count = 0
        for root in self.current_roots():
            candidates = [root] if not root.is_dir() else self.walk_files(root)
            for path in candidates:
                count += 1
                if count > 10000:
                    self.errors["fim.count"] = "Reconciliation limited to 10,000 files; narrow watched paths"
                    return
                self.inspect_file(path)
        with self.spool.lock:
            known = [r[0] for r in self.spool.db.execute("SELECT path FROM files")]
        for path in known:
            if not Path(path).exists():
                self.inspect_file(path)

    @staticmethod
    def walk_files(root):
        for directory, directories, filenames in os.walk(root, followlinks=False):
            directories[:] = sorted(d for d in directories if not (Path(directory) / d).is_symlink())
            for name in sorted(filenames):
                path = Path(directory) / name
                if not path.is_symlink():
                    yield path

    def windows_events(self):
        if os.name != "nt" or not self.config.get("enable_events"):
            return
        for channel in self.configuration.get("channels", []):
            cursor_key = "windows:" + channel
            cursor = self.spool.get(cursor_key, {})
            record = int(cursor.get("record_id", 0))
            encoded_channel = base64.b64encode(channel.encode()).decode()
            script = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);$channel=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded_channel + "'));"
            script += f"$record=[long]{record};try{{if($record -gt 0){{$events=@(Get-WinEvent -LogName $channel -FilterXPath \"*[System[EventRecordID > $record]]\" -Oldest -MaxEvents 100 -ErrorAction Stop)}}else{{$events=@(Get-WinEvent -LogName $channel -MaxEvents 100 -ErrorAction Stop | Sort-Object RecordId)}};$out=@($events | ForEach-Object {{@{{record_id=[string]$_.RecordId;xml=$_.ToXml()}}}});ConvertTo-Json -InputObject $out -Compress -Depth 5}}catch{{if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){{'[]'}}else{{throw}}}}"
            encoded = base64.b64encode(script.encode("utf-16-le")).decode()
            result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], capture_output=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode:
                raise RuntimeError("Windows Event Log query failed: " + result.stderr.decode(errors="replace")[:400])
            if len(result.stdout) > 10 * 1024 * 1024:
                raise ValueError("Windows event query exceeded its bounded response")
            records = json.loads(result.stdout.decode("utf-8-sig"))
            for event in records:
                next_cursor = {"channel": channel, "record_id": str(event["record_id"]), "initial_history_limit": 100}
                self.spool.enqueue(event["xml"].encode(), "windows.event", "windows.event", "application/xml", cursor=next_cursor, cursor_key=cursor_key)

    def linux_journal(self):
        if not sys.platform.startswith("linux") or not self.config.get("enable_events"):
            return
        cursor = self.spool.get("journal", {})
        args = ["journalctl", "--output=json", "--no-pager"]
        if cursor.get("cursor"):
            args.extend(["--after-cursor", cursor["cursor"]])
        else:
            args.extend(["--since", "-5min"])
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        reader = selectors.DefaultSelector()
        reader.register(process.stdout, selectors.EVENT_READ)
        buffer = b""
        count = 0
        deadline = time.monotonic() + 10
        try:
            while count < 100 and time.monotonic() < deadline:
                if not reader.select(timeout=0.2):
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                buffer += chunk
                if len(buffer) > 131072:
                    raise ValueError("Journal record exceeds event limit; source cursor retained")
                while b"\n" in buffer and count < 100:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line:
                        continue
                    data = json.loads(line)
                    timestamp = datetime.fromtimestamp(int(data["__REALTIME_TIMESTAMP"]) / 1000000, timezone.utc).isoformat() if data.get("__REALTIME_TIMESTAMP") else None
                    self.spool.enqueue(line, "linux.journal", "journal.entry", original_timestamp=timestamp, cursor={"cursor": data["__CURSOR"]}, cursor_key="journal")
                    count += 1
            if process.poll() not in (None, 0):
                raise RuntimeError("Journal query failed: " + process.stderr.read(400).decode(errors="replace"))
        finally:
            reader.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()
            process.stderr.close()

    def tail_log(self, path, source_type):
        path = Path(path).resolve()
        if not path.is_file():
            raise ValueError("Configured log file does not exist: " + str(path))
        key = source_type + ":" + str(path)
        cursor = self.spool.get(key, {})
        stat = path.stat()
        identity = f"{stat.st_dev}:{stat.st_ino}"
        offset = int(cursor.get("offset", 0))
        if cursor.get("identity") != identity or stat.st_size < offset:
            if cursor:
                self.spool.enqueue(canon({"summary": "Source log rotated or truncated; uncollected old-file bytes may be unavailable", "path": str(path), "severity": 2}), "collector.health", "source.rotation")
            offset = 0
        with path.open("rb") as source:
            source.seek(offset)
            for _ in range(300):
                line = source.readline(MAX_EVENT + 1)
                if not line:
                    break
                if len(line) > MAX_EVENT:
                    raise ValueError("Log line exceeds 64 KiB; cursor was not advanced")
                if not line.endswith(b"\n"):
                    break
                next_cursor = {"path": str(path), "identity": identity, "offset": source.tell()}
                self.spool.enqueue(line, source_type, "network.observation", "application/json" if line.lstrip().startswith(b"{") else "text/plain", cursor=next_cursor, cursor_key=key)

    def memory_available(self):
        command = self.config.get("memory_command", [])
        if not self.config.get("enable_memory") or not command or not self.config.get("memory_tool_sha256"):
            return False
        tool = Path(command[0])
        return tool.is_absolute() and tool.is_file() and file_hash(tool)[0] == self.config["memory_tool_sha256"] and any("{output}" in a for a in command[1:])

    def acquire(self, job):
        plan = verify_signature(job["signed_plan"], "CBB-ACQUISITION-v1", self.config["server_signing_key"])
        identity = job["id"]
        if plan["acquisition_id"] != identity or plan["collector_id"] != self.config["collector_id"]:
            raise ValueError("Acquisition identity differs from signed authorization")
        if time.time() >= int(plan["expires_at"]):
            raise ValueError("Acquisition authorization expired")
        if plan["template"] not in ("selected-files", "processes", "network", "memory-capture"):
            raise ValueError("Unknown acquisition template")
        if not self.config.get("enable_acquisitions", False):
            raise ValueError("Acquisitions are disabled in local collector policy")
        maximum = min(int(plan["max_bytes"]), int(self.config.get("max_acquisition_bytes", 1024**3)))
        timeout = min(int(plan["timeout_seconds"]), 900)
        if maximum < 1 or timeout < 1:
            raise ValueError("Invalid acquisition bounds")
        with self.spool.lock, self.spool.db:
            previous = self.spool.db.execute("SELECT state FROM acquisitions WHERE id=?", (identity,)).fetchone()
            if previous:
                raise ValueError("Acquisition was already attempted; human review is required before a new authorization")
            self.spool.db.execute("INSERT INTO acquisitions(id,state,updated_at) VALUES(?,'RUNNING',?)", (identity, now()))
        response = self.client.post(f"/api/v1/collector-jobs/{identity}/status", json={"state": "RUNNING", "detail": "Collector accepted signed authorization and local policy"})
        response.raise_for_status()
        target = self.root / "acquisitions" / (identity + (".zip" if plan["template"] == "selected-files" else ".json" if plan["template"] in ("processes", "network") else ".raw"))
        target.parent.mkdir(exist_ok=True)
        deadline = time.monotonic() + timeout
        try:
            if plan["template"] == "selected-files":
                self.collect_files(plan["paths"], target, maximum, deadline)
            elif plan["template"] == "processes":
                items = []
                for process in psutil.process_iter(["pid", "name", "create_time", "username", "cmdline"]):
                    if time.monotonic() >= deadline or len(items) >= 20000:
                        raise TimeoutError("Process collection exceeded its time/count bound")
                    items.append(process.info)
                atomic_write(target, canon({"acquired_at": now(), "template": "processes", "processes": items}))
            elif plan["template"] == "network":
                items = [{"family": str(c.family), "type": str(c.type), "local": list(c.laddr), "remote": list(c.raddr), "status": c.status, "pid": c.pid} for c in psutil.net_connections(kind="inet")]
                if len(items) > 20000:
                    raise ValueError("Network collection exceeds the connection-count bound")
                atomic_write(target, canon({"acquired_at": now(), "template": "network", "connections": items}))
            else:
                if not self.memory_available():
                    raise ValueError("Memory capture requires an explicitly enabled, hash-pinned local tool and output template")
                args = [str(a).replace("{output}", str(target)) for a in self.config["memory_command"]]
                with (target.with_suffix(".tool.log")).open("wb") as output:
                    process = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    try:
                        while process.poll() is None:
                            if time.monotonic() >= deadline or (target.exists() and target.stat().st_size > maximum):
                                raise TimeoutError("Memory capture exceeded its approved time/byte limit")
                            time.sleep(0.2)
                        if process.returncode != 0:
                            raise RuntimeError("Memory tool failed; inspect the local tool log")
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=5)
            if time.monotonic() >= deadline:
                raise TimeoutError("Acquisition exceeded its approved time limit")
            digest, size = file_hash(target, maximum)
            with self.spool.lock, self.spool.db:
                self.spool.db.execute("UPDATE acquisitions SET artifact=?,updated_at=? WHERE id=?", (str(target), now(), identity))
            self.upload_artifact(identity, target, size, digest)
            response = self.client.post(f"/api/v1/collector-jobs/{identity}/status", json={"state": "COMPLETE", "detail": "Artifact uploaded and server digest verified"})
            response.raise_for_status()
            with self.spool.lock, self.spool.db:
                self.spool.db.execute("UPDATE acquisitions SET state='COMPLETE',updated_at=? WHERE id=?", (now(), identity))
        except Exception as ex:
            with self.spool.lock, self.spool.db:
                self.spool.db.execute("UPDATE acquisitions SET state='FAILED',error=?,updated_at=? WHERE id=?", (str(ex)[:500], now(), identity))
            try:
                self.client.post(f"/api/v1/collector-jobs/{identity}/status", json={"state": "FAILED", "detail": str(ex)[:500]}).raise_for_status()
            except Exception:
                log.exception("Could not report failed acquisition; server lease expiry will require review")
            raise

    def collect_files(self, paths, target, maximum, deadline):
        manifest = []
        total = 0
        source_paths = []
        roots = self.current_roots()
        for candidate in paths:
            path = Path(candidate).resolve()
            if not inside(path, roots) or not inside(path, self.local_roots) or inside(path, [self.root]):
                raise ValueError("Acquisition path exceeds central and local allowlists")
            for source in (self.walk_files(path) if path.is_dir() else [path]):
                source_paths.append(source)
                if len(source_paths) > 10000:
                    raise ValueError("Acquisition exceeds 10,000 files")
        with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_STORED) as package:
            for index, path in enumerate(dict.fromkeys(source_paths)):
                if time.monotonic() >= deadline:
                    raise TimeoutError("File acquisition timeout")
                if not path.is_file() or path.is_symlink() or not inside(path, roots):
                    raise ValueError("Source path is unavailable, a link, or outside the allowlist")
                before = path.stat()
                total += before.st_size
                if total + 1024 * (index + 1) > maximum:
                    raise ValueError("Acquisition exceeds its approved byte limit")
                member = f"files/{index:05d}_{path.name}"
                digest = hashlib.sha256()
                with path.open("rb") as source, package.open(member, "w") as dest:
                    while chunk := source.read(1024 * 1024):
                        if time.monotonic() >= deadline:
                            raise TimeoutError("File acquisition timeout")
                        digest.update(chunk)
                        dest.write(chunk)
                after = path.stat()
                if before.st_mtime_ns != after.st_mtime_ns or before.st_size != after.st_size:
                    raise ValueError("Source file changed during acquisition; artifact is incomplete and requires review")
                manifest.append({"path": str(path), "member": member, "size": str(before.st_size), "sha256": digest.hexdigest(), "mtime_ns": str(before.st_mtime_ns)})
            package.writestr("acquisition-manifest.json", canon({"acquired_at": now(), "files": manifest, "consistency": "Per-file before/after metadata checked; this is not an atomic filesystem snapshot"}))

    def upload_artifact(self, acquisition_id, target, size, digest):
        response = self.client.post("/api/v1/uploads", json={"acquisition_id": acquisition_id, "name": target.name, "size": size, "sha256": digest})
        response.raise_for_status()
        upload = response.json()
        upload_id = upload["upload_id"]
        with self.spool.lock, self.spool.db:
            self.spool.db.execute("UPDATE acquisitions SET upload_id=?,updated_at=? WHERE id=?", (upload_id, now(), acquisition_id))
        chunk_bytes = int(upload["chunk_bytes"])
        if not 1 <= chunk_bytes <= 8 * 1024 * 1024:
            raise ValueError("Server requested an invalid chunk size")
        received = set(upload.get("received_parts", []))
        with target.open("rb") as stream:
            index = 0
            while data := stream.read(chunk_bytes):
                if index not in received:
                    for attempt in range(3):
                        try:
                            response = self.client.put(f"/api/v1/uploads/{upload_id}/chunks/{index}", content=data, headers={"Content-Type": "application/octet-stream"})
                            response.raise_for_status()
                            break
                        except (httpx.TransportError, httpx.HTTPStatusError):
                            if attempt == 2:
                                raise
                            time.sleep(2 ** attempt)
                index += 1
        response = self.client.post(f"/api/v1/uploads/{upload_id}/complete", json={})
        response.raise_for_status()
        return response.json()

    def poll_acquisition(self):
        if not self.config.get("enable_acquisitions"):
            return
        response = self.client.get("/api/v1/collector-jobs")
        response.raise_for_status()
        job = response.json().get("job")
        if job:
            self.acquire(job)

    def cycle(self, reconcile=False):
        def deliver():
            for _ in range(4):
                self.flush()
                backlog=self.spool.status()
                if backlog['queued']<100 and backlog['awaiting_seal']<100:break
        operations = [("heartbeat", self.heartbeat), ("transport", deliver), ("windows", self.windows_events), ("journal", self.linux_journal)]
        from .firewall import tail_firewall
        for path in self.config.get('firewall_files', []):
            operations.append(('firewall:' + path, lambda p=path: tail_firewall(self, p)))
        for path in self.config.get("eve_files", []):
            operations.append(("eve:" + path, lambda p=path: self.tail_log(p, "suricata.eve")))
        for path in self.config.get("zeek_files", []):
            operations.append(("zeek:" + path, lambda p=path: self.tail_log(p, "zeek")))
        if reconcile:
            operations.append(("fim", self.reconcile_files))
        while not self.changed.empty():
            path = self.changed.get_nowait()
            operations.append(("fim.event", lambda p=path: self.inspect_file(p)))
        operations.append(("acquisition", self.poll_acquisition))
        for name, operation in operations:
            try:
                operation()
                self.errors.pop(name, None)
            except Exception as ex:
                self.errors[name] = str(ex)[:500]
                log.warning("%s: %s", name, str(ex)[:500])
        return self.health()

    def close(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        self.client.close()
        self.spool.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="agent-data/agent.json", help="Local collector credentials and policy file; do not commit it")
    parser.add_argument('--stop-file', type=Path, help='Exit after the current cycle when the launcher creates this file')
    commands = parser.add_subparsers(dest="command", required=True)
    enrollment = commands.add_parser("enroll", help="Consume a ten-minute enrollment token and save pinned credentials")
    enrollment.add_argument("--server", required=True)
    enrollment.add_argument("--token", help="Enrollment token; omit to read CBB_ENROLLMENT_TOKEN")
    enrollment.add_argument("--server-key", required=True, help="Deployment signing key verified through an independent trusted channel")
    enrollment.add_argument("--name", default=os.environ.get("COMPUTERNAME", "Collector"))
    enrollment.add_argument("--allow-path", action="append", default=[])
    enrollment.add_argument("--enable-events", action="store_true")
    enrollment.add_argument("--enable-acquisitions", action="store_true")
    enrollment.add_argument("--eve-file", action="append", default=[])
    enrollment.add_argument('--firewall-file', action='append', default=[])
    enrollment.add_argument("--zeek-file", action="append", default=[])
    enrollment.add_argument("--yara-rules")
    enrollment.add_argument("--ca-file")
    enrollment.add_argument("--cert-file")
    enrollment.add_argument("--key-file")
    commands.add_parser("run", help="Run configured sources and durable delivery until stopped")
    commands.add_parser("once", help="Perform one collection/delivery cycle and print health")
    commands.add_parser("status", help="Inspect local queue and policy without contacting the server")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    path = Path(args.config).resolve()
    if args.command == "enroll":
        if path.exists():
            parser.error("Config already exists; use a separate directory for a new collector")
        token = args.token or os.getenv("CBB_ENROLLMENT_TOKEN", "")
        if not token:
            parser.error("Supply --token or CBB_ENROLLMENT_TOKEN")
        config = {"server": args.server.rstrip("/"), "data": str(path.parent), "allowed_paths": [str(Path(p).resolve()) for p in args.allow_path], "enable_events": args.enable_events, "enable_acquisitions": args.enable_acquisitions, "eve_files": [str(Path(p).resolve()) for p in args.eve_file], "zeek_files": [str(Path(p).resolve()) for p in args.zeek_file], "yara_rules": str(Path(args.yara_rules).resolve()) if args.yara_rules else None, "ca_file": args.ca_file, "cert_file": args.cert_file, "key_file": args.key_file}
        config['firewall_files'] = [str(Path(p).resolve()) for p in args.firewall_file]
        with secure_client(config, enrollment=True) as client:
            response = client.post("/api/v1/collectors/enroll", json={"token": token, "name": args.name})
            response.raise_for_status()
            result = response.json()
        if result["server_signing_key"] != args.server_key:
            raise ValueError("Enrollment returned a different signing key; credentials were not saved")
        config.update(result)
        atomic_write(path, json.dumps(config, indent=2).encode())
        if os.name != "nt":
            path.parent.chmod(0o700)
            path.chmod(0o600)
        print(json.dumps({"collector_id": result["collector_id"], "config": str(path), "next": "Configure matching watched paths in the GUI, then run the agent"}, indent=2))
        return
    config = json.loads(path.read_text())
    data_root = Path(config.get("data", str(path.parent))).resolve()
    if args.command == "status":
        spool = Spool(data_root)
        print(json.dumps({"collector_id": config["collector_id"], "server": config["server"], "spool": spool.status(), "configured_paths": spool.get("configuration", {}).get("paths", [])}, indent=2))
        spool.close()
        return
    data_root.mkdir(parents=True, exist_ok=True)
    from .cli import exclusive
    with exclusive(data_root):
        run_collection(config,data_root,args)


def run_collection(config,data_root,args):
    handler = RotatingFileHandler(data_root / "agent.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.getLogger().addHandler(handler)
    agent = Agent(config, data_root)
    try:
        if args.command == "once":
            print(json.dumps(agent.cycle(reconcile=True), indent=2))
        else:
            cycle = 0
            failures = 0
            while not (args.stop_file and args.stop_file.exists()):
                agent.cycle(reconcile=cycle % 12 == 0)
                cycle += 1
                failures = failures + 1 if "heartbeat" in agent.errors or "transport" in agent.errors else 0
                delay = max(2, min(60, int(agent.configuration.get("poll_seconds", 5)) * 2 ** min(failures, 4)))
                time.sleep(delay + random.uniform(0, delay * 0.1))
    except KeyboardInterrupt:
        log.info("Collector stopped; unsent events remain in the durable spool")
    finally:
        agent.close()
        handler.close()
        logging.getLogger().removeHandler(handler)


if __name__ == "__main__":
    main()
