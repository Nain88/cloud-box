from dataclasses import dataclass, field
from pathlib import Path
import os


@dataclass
class Settings:
    data: Path = field(default_factory=lambda: Path(os.getenv("CBB_DATA", "data")).resolve())
    mode: str = field(default_factory=lambda: os.getenv("CBB_MODE", "virtual"))
    database_url: str = field(default_factory=lambda: os.getenv("CBB_DATABASE_URL", ""))
    public_url: str = field(default_factory=lambda: os.getenv("CBB_PUBLIC_URL", "http://127.0.0.1:8765"))
    secure_cookies: bool = field(default_factory=lambda: os.getenv("CBB_SECURE_COOKIES", "false").lower() == "true")
    workers: bool = field(default_factory=lambda: os.getenv("CBB_WORKERS", "true").lower() == "true")
    segment_bytes: int = 64 * 1024 * 1024
    checkpoint_seconds: int = 300
    max_event_bytes: int = 65536
    max_batch_bytes: int = 1048576
    max_artifact_bytes: int = 4 * 1024**3
    signer_url: str = field(default_factory=lambda: os.getenv("CBB_SIGNER_URL", ""))
    signer_token: str = field(default_factory=lambda: os.getenv("CBB_SIGNER_TOKEN", ""))
    witness_url: str = field(default_factory=lambda: os.getenv("CBB_WITNESS_URL", ""))
    witness_public_key: str = field(default_factory=lambda: os.getenv("CBB_WITNESS_PUBLIC_KEY", ""))
    witness_independent: bool = field(default_factory=lambda: os.getenv("CBB_WITNESS_INDEPENDENT", "false").lower() == "true")
    require_mtls: bool = field(default_factory=lambda: os.getenv("CBB_REQUIRE_MTLS", "false").lower() == "true")
    proxy_secret: str = field(default_factory=lambda: os.getenv("CBB_PROXY_SECRET", ""))
    s3_bucket: str = field(default_factory=lambda: os.getenv("CBB_S3_BUCKET", ""))
    s3_endpoint: str = field(default_factory=lambda: os.getenv("CBB_S3_ENDPOINT", ""))
    s3_retention_days: int = field(default_factory=lambda: int(os.getenv("CBB_S3_RETENTION_DAYS", "90")))
    s3_retention_mode: str = field(default_factory=lambda: os.getenv("CBB_S3_RETENTION_MODE", "GOVERNANCE"))
    retention_days: int = 90
    allow_self_approval: bool = field(default_factory=lambda: os.getenv("CBB_ALLOW_SELF_APPROVAL", "false").lower() == "true")

    def prepare(self):
        self.data.mkdir(parents=True, exist_ok=True)
        for name in ("archive", "inbox", "keys", "exports", "uploads", "models", "checkpoints", "artifacts"):
            (self.data / name).mkdir(exist_ok=True)
        if not self.database_url:
            self.database_url = "sqlite:///" + str(self.data / "cbb.sqlite3").replace("\\", "/")
        if self.mode not in ("virtual", "cloud"):
            raise ValueError("CBB_MODE must be virtual or cloud")
        if self.mode == "cloud":
            if not self.database_url.startswith("postgresql"):
                raise ValueError("Cloud Mode requires PostgreSQL")
            if not self.secure_cookies or not self.public_url.startswith("https://"):
                raise ValueError("Cloud Mode requires HTTPS and secure cookies")
            if not self.require_mtls or len(self.proxy_secret) < 32:
                raise ValueError("Cloud Mode requires authenticated mTLS proxy forwarding")
            if not self.signer_url or len(self.signer_token) < 32:
                raise ValueError("Cloud Mode requires the separate signer service")
        return self

