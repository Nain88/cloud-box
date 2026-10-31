# Deployment and operations

## Native Windows Virtual Mode

Use the root launcher. Native runtime requires Python 3.12+, approximately 3 GB of dependency space, and a browser. Budget 4 CPU cores, 8 GB RAM minimum (16 GB recommended) and 20 GB free disk for a modest demonstration. Reserve at least twice the expected evidence size for exports and backups. These are planning budgets, not measured throughput guarantees. Virtual Mode listens on loopback; do not expose its development HTTP listener to the internet.

The first-run token is `data/keys/bootstrap.token`. It is removed after account creation. Protect this folder using Windows user ACLs and disk encryption. Store copies of the public signing key separately. Keep private signing keys and database backups confidential.

Docker Virtual Mode is optional: `docker compose -f compose.virtual.yml up --build -d`. Read the token using `docker compose -f compose.virtual.yml exec app cat /data/keys/bootstrap.token`. Its host port is bound to 127.0.0.1. Docker Desktop must be installed separately.

## Linux Cloud Mode

Use a dedicated Linux VM with Docker Engine and Compose, 4 vCPU, 8 GB RAM and provisioned persistent disk. Configure DNS and an actual HTTPS certificate first. Cloud startup rejects SQLite, insecure cookies, missing mTLS forwarding secrets or an absent external signer.

1. Copy `deploy/cloud.env.example` to `.env`. Set the domain and three **distinct** random 32-byte hex secrets. Generate each using `python -c "import secrets;print(secrets.token_hex(32))"`. Never commit `.env`.
2. Put the server certificate chain in `secrets/tls/server.crt`, its key in `server.key`, and the trusted collector issuing CA certificate in `client-ca.crt`. Use your institution's PKI or a reviewed private CA. Issue individual collector certificates with client-auth usage. Do not use the server key on collectors.
3. `docker compose -f compose.cloud.yml --env-file .env config` must succeed. Then `docker compose -f compose.cloud.yml --env-file .env up --build -d`.
4. Read `/data/keys/bootstrap.token` through `docker compose ... exec app cat ...` and complete HTTPS setup. The signer and PostgreSQL have no public host ports. Only Nginx exposes 443.
5. Enroll each collector, configure its CA/client certificate/private key, and bind its PEM certificate in Administration. The proxy verifies the CA and the API verifies the registered SHA-256 certificate fingerprint. Enrollment uses the expiring token before certificate binding. The proxy strips caller-supplied forwarding headers.
6. Review `docker compose ... logs`, `/health/ready`, the GUI worker diagnostics and a trial import/export before collecting real data.

The bundled Suricata binary in the image is inactive until a reviewed YAML configuration is mounted and `CBB_SURICATA_CONFIG` points to it. Set `CBB_SURICATA_EXECUTABLE=/usr/bin/suricata`. Enable EVE output and install a reviewed ruleset. The PCAP adapter uses offline `-r` processing; it does not grant live packet capture privileges. Test a known PCAP with documented expected output. An empty result is reported honestly.

## Signing and independent witnessing

The cloud signer runs on a separate service with its own volume. Same-host separation does not protect against host root. For stronger separation deploy it on another controlled host behind authenticated TLS. Never publish its bearer token.

On an independently administered machine, run `python -m cbb.witness --data witness-data --trusted-key <deployment-public-key>`. Its default listener is 127.0.0.1:8767; publish through an HTTPS proxy. Obtain the witness public key from `/public-key`, verify it out of band, and set `CBB_WITNESS_URL`, `CBB_WITNESS_PUBLIC_KEY` and `CBB_WITNESS_INDEPENDENT=true` on the app. Start witnessing at checkpoint 1. The app submits pending checkpoints in order. A witness on the same laptop is a functional demonstration, not an independent trust domain.

A signed checkpoint lost between external signing and database commit fails closed on retry. Preserve both volumes and reconcile the recorded signed checkpoint before resuming. Never reset signer sequence state to conceal a fork.

## Object storage

Configure an existing S3-compatible bucket with versioning and Object Lock enabled, a workload IAM role, and the `CBB_S3_*` variables. The role requires versioned PutObject/GetObject and retention operations. Do not give the application governance-bypass permission. Trigger replication in Administration; the adapter verifies downloaded segment SHA-256 and records version IDs. Retain local copies. A bucket on the same compromised host provides no independent assurance. Validate the actual provider's retention semantics before claiming WORM protection.

## Backup and restore

Stop the native server. For SQLite use `python -m cbb.cli --data data backup backups/run-001`. The destination must be new and outside the live directory. The backup contains private keys; encrypt it and restrict access. Restore into an empty target using `python -m cbb.cli --data restored-data restore backups/run-001 --checkpoint independently-retained-checkpoint.json`. Inspect the result before starting. Local validation without an external checkpoint cannot detect a complete rollback of both database and local proof.

For cloud backups, stop app writes, take `pg_dump -Fc` of the database, and snapshot the archive and signer volumes at the same stopped point. Preserve external witness state separately. Restore into an isolated deployment, verify archive/checkpoint continuity, compare the latest independently held checkpoint and only then resume. PostgreSQL restore has not been exercised in this Windows workspace. Never replace a newer witnessed deployment with an older backup without a documented new epoch/recovery decision.

Evidence is retained indefinitely by default. Case holds are recorded; this revision offers no automatic destructive expiry. Monitor disk usage and provision more space or perform an approved offline archival procedure. The server rejects ingestion near exhaustion, and collector spools report capacity failures rather than silently discard.

## Development and release

Run the Python tests and `pnpm --dir web build`. For Vite development set `CBB_PUBLIC_URL=http://127.0.0.1:5173`; Vite proxies `/api` to 8765. Use the same hostname consistently because cookies and origin checks are deliberate. Use one application worker per archive; scaling the sealer is outside this release.

Pin images by reviewed digest for deployment, scan the dependency lock and image, rotate bootstrap/collector credentials as required, and execute the Linux, mTLS, S3, recovery, acquisition and workload tests listed in IMPLEMENTATION_STATUS before a production release.

## MEGA, AI and WSL sensors

See INTEGRATIONS-GUIDE.md. MEGAcmd must be installed and logged in under the service OS account; its credentials are not in the container image. Container-to-host MEGAcmd IPC is not configured by the supplied Compose files. Use a properly configured native Linux service session for MEGA, or the existing S3 adapter. The optional Ollama endpoint is loopback-only; a separate container endpoint requires an explicitly revised trusted deployment profile. None of these adapters establish cloud production readiness without destination tests.
