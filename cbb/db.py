from contextlib import contextmanager
from threading import RLock
from sqlalchemy import (create_engine, MetaData, Table, Column, String, Text, Integer,
                        BigInteger, Boolean, LargeBinary, Float, ForeignKey, UniqueConstraint, event, text)

meta = MetaData()
def table(name, *cols): return Table(name, meta, *cols)
def idcol(name="id"): return Column(name, String(64), primary_key=True)
def txt(name, **kw): return Column(name, Text, **kw)
def num(name, **kw): return Column(name, BigInteger, **kw)
users = table("users", idcol(), txt("username", unique=True, nullable=False), txt("password_hash"), txt("role"), txt("created_at"), Column("active", Boolean, default=True), txt("totp_secret"), Column("last_totp_counter", BigInteger, default=-1))
sessions = table("sessions", idcol(), Column("user_id", String(64), ForeignKey("users.id")), txt("token_hash", unique=True), txt("csrf"), Column("created", Float), Column("last_seen", Float))
assets = table("assets", idcol(), txt("name"), txt("os"), Column("criticality", Integer, default=3))
collectors = table("collectors", idcol(), Column("asset_id", String(64), ForeignKey("assets.id")), txt("name"), txt("token_hash", unique=True), txt("cert_fingerprint"), txt("state"), txt("created_at"), txt("last_heartbeat"), txt("health"), txt("configuration"), Column("config_version", Integer, default=1))
enrollments = table("enrollments", idcol(), txt("token_hash", unique=True), txt("name"), txt("os"), Column("expires", Float), Column("used", Boolean, default=False))
chains = table("chains", idcol(), txt("purpose", unique=True), txt("genesis"), num("head_sequence", default=0), txt("head_hash"))
receipts = table("receipts", idcol(), Column("collector_id", String(64), ForeignKey("collectors.id")), txt("boot_id"), txt("source_seq"), txt("payload_hash"), txt("payload"), txt("evidence_id", unique=True), txt("state"), txt("received_at"), txt("error"), UniqueConstraint("collector_id", "boot_id", "source_seq"))
segments = table("raw_segments", idcol(), txt("path"), num("size", default=0), txt("created_at"), Column("closed", Boolean, default=False), txt("sha256"), txt("remote"))
evidence = table("evidence", idcol(), Column("chain_id", String(64), ForeignKey("chains.id")), num("sequence"), Column("collector_id", String(64), ForeignKey("collectors.id")), Column("asset_id", String(64), ForeignKey("assets.id")), Column("segment_id", String(64), ForeignKey("raw_segments.id")), num("raw_offset"), num("raw_length"), txt("raw_sha256"), Column("envelope", LargeBinary), txt("envelope_sha256"), txt("previous_hash"), txt("record_hash"), txt("source_type"), txt("event_type"), txt("occurred_at"), txt("received_at"), Column("severity", Integer), txt("summary"), UniqueConstraint("chain_id", "sequence"))
custody = table("custody_entries", idcol(), num("sequence", unique=True), Column("envelope", LargeBinary), txt("previous_hash"), txt("entry_hash"), txt("actor"), txt("action"), txt("target"), txt("created_at"))
checkpoints = table("checkpoints", idcol(), num("sequence", unique=True), txt("document"), txt("sha256"), txt("created_at"))
witness_receipts = table("witness_receipts", idcol(), txt("checkpoint_id", unique=True), txt("receipt"), Column("independent", Boolean), txt("created_at"))
cases = table("cases", idcol(), txt("title"), txt("description"), Column("owner_id", String(64), ForeignKey("users.id")), txt("status"), Column("severity", Integer), Column("version", Integer), Column("hold", Boolean, default=True), txt("conclusion"), txt("created_at"), txt("updated_at"))
case_members = table("case_members", Column("case_id", String(64), ForeignKey("cases.id"), primary_key=True), Column("user_id", String(64), ForeignKey("users.id"), primary_key=True))
case_evidence = table("case_evidence", idcol(), Column("case_id", String(64), ForeignKey("cases.id")), Column("evidence_id", String(64), ForeignKey("evidence.id")), num("case_version"), Column("active", Boolean), txt("reason"), txt("created_at"))
notes = table("notes", idcol(), Column("case_id", String(64), ForeignKey("cases.id")), txt("author_id"), txt("body"), txt("previous_id"), txt("created_at"))
jobs = table("jobs", idcol(), txt("kind"), txt("state"), txt("actor_id"), txt("case_id"), txt("payload"), txt("result"), txt("error"), Column("progress", Integer, default=0), Column("attempts", Integer, default=0), Column("next_attempt", Float, default=0), txt("operation_key", unique=True), txt("created_at"), txt("updated_at"))
alerts = table("alerts", idcol(), txt("evidence_id"), txt("asset_id"), txt("rule_id"), Column("severity", Integer), Column("risk", Float), txt("explanation"), txt("status"), txt("decision"), txt("model_id"), txt("components"), txt("created_at"), txt("dedup_key", unique=True))
incidents = table("incidents", idcol(), txt("asset_id"), txt("title"), Column("confidence", Float), txt("rule_id"), Column("version", Integer), txt("evidence_ids"), txt("decisions"), txt("created_at"), txt("dedup_key", unique=True))
verifications = table("verification_runs", idcol(), txt("job_id"), txt("result"), txt("created_at"))
models = table("model_versions", idcol(), txt("name"), txt("sha256"), txt("manifest"), txt("created_at"), Column("active", Boolean))
acquisitions = table("acquisitions", idcol(), txt("case_id"), txt("collector_id"), txt("actor_id"), txt("approver_id"), txt("state"), txt("plan"), txt("signed_plan"), txt("reason"), txt("created_at"), txt("updated_at"), Column("expires", Float), Column("lease_until", Float), txt("result"))
uploads = table("uploads", idcol(), txt("acquisition_id"), txt("collector_id"), txt("name"), num("size"), txt("sha256"), txt("parts"), txt("state"), Column("expires", Float), txt("artifact_id"))
artifacts = table("artifacts", idcol(), txt("path"), txt("name"), num("size"), txt("sha256"), txt("evidence_id"), txt("case_id"), txt("created_at"))
exports = table("export_packages", idcol(), txt("case_id"), num("case_version"), txt("path"), txt("sha256"), txt("manifest"), txt("created_at"))
config = table("configuration", idcol(), txt("value"), num("version", default=1), txt("updated_at"))
dispositions = table("dispositions", idcol(), txt("segment_id"), txt("manifest"), txt("created_at"))
cloud_objects = table("cloud_objects", idcol(), txt("provider"), txt("source_kind"), txt("source_id"), txt("local_path"), txt("remote_path"), txt("sha256"), num("size"), txt("state"), txt("verified_at"), txt("created_at"), UniqueConstraint("provider","local_path","sha256"))
ai_runs = table("ai_runs", idcol(), txt("case_id"), txt("actor_id"), txt("engine"), txt("question"), txt("input_sha256"), txt("output_sha256"), txt("document"), txt("review"), txt("created_at"))


class Database:
    def __init__(self, url):
        self.sqlite = url.startswith("sqlite")
        self.engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30} if self.sqlite else {}, pool_pre_ping=True)
        self.lock = RLock()
        if self.sqlite:
            @event.listens_for(self.engine, "connect")
            def pragmas(conn, _):
                cur = conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA synchronous=FULL")
                cur.close()
        meta.create_all(self.engine)
        with self.engine.begin() as c:
            if self.sqlite:
                for name in ("evidence", "custody_entries", "checkpoints", "notes"):
                    for op in ("UPDATE", "DELETE"):
                        c.execute(text(f"CREATE TRIGGER IF NOT EXISTS immutable_{name}_{op} BEFORE {op} ON {name} BEGIN SELECT RAISE(ABORT, 'immutable table'); END"))
            else:
                c.execute(text("CREATE OR REPLACE FUNCTION cbb_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable table'; END $$"))
                for name in ("evidence", "custody_entries", "checkpoints", "notes"):
                    c.execute(text(f"DROP TRIGGER IF EXISTS immutable_{name} ON {name}"))
                    c.execute(text(f"CREATE TRIGGER immutable_{name} BEFORE UPDATE OR DELETE ON {name} FOR EACH ROW EXECUTE FUNCTION cbb_immutable()"))

    @contextmanager
    def tx(self):
        with self.lock, self.engine.connect() as c:
            if self.sqlite: c.exec_driver_sql("BEGIN IMMEDIATE")
            else: c.execute(text("SELECT pg_advisory_xact_lock(643022901)"))
            try:
                yield c
                c.commit()
            except BaseException:
                c.rollback()
                raise

    @contextmanager
    def read(self):
        with self.engine.connect() as c:
            if self.sqlite:c.exec_driver_sql("BEGIN")
            else:c=c.execution_options(isolation_level="REPEATABLE READ")
            try:yield c
            finally:c.rollback()

