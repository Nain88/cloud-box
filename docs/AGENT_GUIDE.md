# Cyber Black Box collector guide

The collector is real software for Windows and Linux. It only reads sources an operator enables. Installing it does not enable Windows auditing, Sysmon, Security-log access, packet interception, a memory driver, or broad disk collection. Use an authorized laboratory or systems you administer.

## Enrollment and trust

1. Start the server and complete administrator setup. Create a collector enrollment token in **Collectors**. A token expires after ten minutes and is consumed once.
2. Obtain the deployment's Ed25519 public key from the operator over a separately trusted channel. Do not trust a replacement key merely because a network response supplied it.
3. Enroll from the project directory. The examples use a local Windows server and an intentionally narrow watched folder:

```powershell
$env:CBB_ENROLLMENT_TOKEN = 'paste-the-one-time-token'
.\.venv\Scripts\python.exe -m cbb.agent --config .\agent-data\agent.json enroll --server http://127.0.0.1:8765 --server-key 'paste-pinned-public-key' --name 'Windows laboratory' --allow-path 'C:\CBB-Lab\watched' --yara-rules .\deploy\agent\lab-rules.yar
Remove-Item Env:CBB_ENROLLMENT_TOKEN
```

The saved `agent.json` contains a bearer credential. Keep it private and out of version control. On Windows, grant its directory only the collector account and administrators using normal NTFS permissions. Enrollment sets restrictive Unix permissions automatically. Never duplicate a collector identity onto a second machine.

4. In **Collectors**, edit that collector's central configuration to watch exactly the permitted folder. A central path must be within a local `allowed_paths` entry. A signed server configuration cannot expand local permission. Until central and local paths agree, no files are monitored.
5. Run one cycle, inspect health, and then start continuous collection:

```powershell
.\.venv\Scripts\python.exe -m cbb.agent --config .\agent-data\agent.json once
.\.venv\Scripts\python.exe -m cbb.agent --config .\agent-data\agent.json status
.\.venv\Scripts\python.exe -m cbb.agent --config .\agent-data\agent.json run
```

`once` collects after its initial delivery pass. Newly collected records remain in the local spool until a subsequent cycle sends them. **Queued**, **awaiting seal**, **quarantined**, and **blocked** have different meanings; an HTTP acceptance is not yet a sealed evidence record.

## Cloud TLS and client certificates

Remote HTTP is rejected. Use HTTPS with normal hostname and certificate-chain validation. A private CA can be supplied as `--ca-file`; there is no insecure certificate-check bypass. Enrollment also accepts `--cert-file` and `--key-file`:

```bash
export CBB_ENROLLMENT_TOKEN='one-time-token'
.venv/bin/python -m cbb.agent --config /var/lib/cbb-agent/agent.json enroll \
  --server https://cbb.example.edu --server-key 'independently-verified-base64-key' \
  --name 'Linux laboratory' --allow-path /srv/cbb-lab/watched \
  --ca-file /etc/cbb-agent/ca.pem --cert-file /etc/cbb-agent/collector.pem \
  --key-file /etc/cbb-agent/collector-key.pem
unset CBB_ENROLLMENT_TOKEN
```

Cloud deployment requires a CA-issued client certificate. The administrator must bind the public certificate PEM to the enrolled collector in the GUI before normal heartbeat/intake can succeed. The application checks the SHA-256 fingerprint of the presented certificate against this binding. The reverse proxy must independently validate the client certificate chain, require `ssl_client_verify=SUCCESS` for collector routes, strip incoming identity headers, and set its own `X-Proxy-Secret` and escaped `X-Client-Cert`. Never expose the backend port to untrusted clients.

The agent sends its own certificate in the TLS handshake; it never manufactures trusted proxy headers. Keep the CA signing key off the endpoint. Expired or revoked certificates and incorrect bindings must be corrected by an administrator; the agent will retain queued evidence and report failed transport.

## Sources and their boundaries

| Source | Enablement | What is actually collected | Bounds and limitations |
|---|---|---|---|
| Windows Event Log | Enrollment `--enable-events`, or local `enable_events: true`; central channels | Raw XML from `Get-WinEvent`; System/Application/Security/Sysmon channels when present and readable | 100 events per channel per cycle; first read includes at most the latest 100 events. Windows permissions and source retention govern available history. |
| Linux journal | Local `enable_events: true` | Original JSON journal records and durable journal cursors | First read starts five minutes before enrollment polling; 100 records per cycle. Journal access often requires membership in `systemd-journal`. |
| File integrity | Local and central path allowlists | File SHA-256, size, baseline/modified/deleted observations | 20 MiB maximum scanned file, 10,000-file reconciliation bound. Watchdog events plus periodic reconciliation recover current state, not every intermediate modification. |
| YARA | `--yara-rules /absolute/rules.yar` | Rule names/tags, exact file digest and rule-file digest for a match | Real `yara-python`, three-second scan timeout. The included rule detects a harmless lab marker; it is not a general malware feed. |
| Suricata EVE | Repeat `--eve-file /path/eve.json` | Original newline-terminated records from an existing sensor output | The collector does not install or start a packet sensor. File position is persisted. Rotation/truncation can lose unread old-file records and produces a health observation. |
| Zeek | Repeat `--zeek-file /path/conn.log` | Original Zeek JSON or text log lines | JSON output offers richer normalization. Original text is retained even where no dedicated parser extracts every Zeek field. |

Source records over 64 KiB are not silently truncated. The affected source pauses without advancing its cursor and reports an error; review the source or use an artifact acquisition/import workflow. Security-log auditing and Sysmon installation are explicit administrator tasks. This project does not claim to observe events the operating system never generated or retained.

## Queue, recovery and diagnostics

The SQLite spool uses WAL and full synchronization. Each event and its source cursor commit together. Delivery retries use stable boot/sequence identities, so a repeated network send is deduplicated by the server. Raw queued data is deleted locally only after the server reports **SEALED**. Quarantined records remain available locally and are rechecked after server-side replay.

Default spool capacity is 512 MiB; collection pauses before exceeding it or when free disk space falls below 50 MiB. The agent reports that gap. Source logs may rotate while collection is paused, so eventual completeness is not guaranteed. The continuous runner backs off failed connections up to about one minute with jitter. Local rotating logs occupy at most approximately 20 MiB (`agent.log` plus three backups).

Keep the entire configured `data` directory when upgrading or moving the service. Deleting `spool.sqlite3` resets durable cursor/sequence history, loses unsent records and can cause deduplication conflicts. Stop the collector before copying its data. If the identity is lost, revoke it and enroll a new collector instead of inventing a new sequence for the old identity.

## Approved acquisitions

Local `enable_acquisitions` is false by default; enable it deliberately. The UI workflow requires a reason, case, collector, fixed template, byte limit and timeout. A separate approver signs the authorization unless the server was explicitly configured for a development self-approval exception.

The collector verifies the pinned signature, collector identifier, expiry, supported template, local policy and path allowlists before execution. It records an execution attempt durably before capture. A restarted process does not blindly repeat an interrupted acquisition; it marks it for review. Files are copied into a ZIP with original-path, size and SHA-256 manifest entries. Per-file before/after metadata checks detect some concurrent changes; this is not an atomic volume snapshot. Process and network templates use bounded `psutil` snapshots. Acquisition can pause this collector's source polling while it runs; retained OS logs and file reconciliation reduce, but do not eliminate, observation gaps.

Artifacts upload in 4 MiB chunks with idempotent chunk retries. Both the artifact's byte count and complete SHA-256 are verified by the server before completion. Interrupted captures and failed uploads are retained locally for review; do not treat their files as a completed server acquisition. The initial local maximum is 1 GiB even when a larger server plan is approved.

### Optional memory capture

Memory capture requires an external, platform-appropriate tool. No memory driver or utility is bundled or silently installed. The local policy must set all of the following after operator review:

```json
{
  "enable_acquisitions": true,
  "enable_memory": true,
  "memory_command": ["C:\\ApprovedTools\\capture-tool.exe", "{output}"],
  "memory_tool_sha256": "replace-with-verified-sha256-of-that-exact-executable",
  "max_acquisition_bytes": 4294967296
}
```

The command above illustrates the configuration shape only; use the actual supported arguments of the reviewed tool. Its first argument must be an absolute executable path; its SHA-256 must match the configured value; an argument must contain `{output}`. The server sees `memory_capture: true` only when these checks succeed. The remote plan cannot supply executable names or arbitrary command arguments. Capture is bounded by the signed time/byte limits and may require privileges unavailable to the default service account. Verify capture-tool licensing, OS compatibility and output on your lab system before relying on it. A memory dump may contain credentials and personal data; keep its evidence case and export access restricted.

## Persistent operation

### Windows logon task

After verifying `once`, explicitly run:

```powershell
.\deploy\agent\install-windows-task.ps1 -ProjectDirectory 'C:\path\to\cloud box' -ConfigPath 'C:\path\to\cloud box\agent-data\agent.json' -StartNow
```

The task runs as the installing user, with limited privileges, at that user's sign-in. It stops when the user signs out; it is suitable for Virtual Mode and is not an always-on Windows service. `-RunElevated` is an explicit alternative for sources needing administrative rights and must be installed from an administrator PowerShell window. The script never elevates itself or overwrites an existing task. Inspect the task in Windows Task Scheduler. To remove it, run `remove-windows-task.ps1`; removal preserves collector data.

### Linux systemd service

Use an installation path without spaces, such as `/opt/cyber-black-box`, and an enrolled configuration whose `data` is `/var/lib/cbb-agent`. Install dependencies in that project's `.venv` first. Keep existing spool history at `/var/lib/cbb-agent`. Then explicitly run:

```bash
sudo bash deploy/agent/install-linux.sh /opt/cyber-black-box /var/lib/cbb-agent/agent.json
# Grant cbb-agent read permissions only to the approved watched paths, certificate files and sources.
# If journal collection is required, explicitly grant the systemd-journal group where supported.
sudo systemctl enable --now cbb-agent
sudo systemctl status cbb-agent
sudo journalctl -u cbb-agent -n 50 --no-pager
```

The installer creates a dedicated unprivileged account and restrictive service unit, refuses to overwrite an existing installation, and does not automatically start it. Ensure existing spool files are owned by `cbb-agent` before starting; the script does not recursively change ownership of an existing evidence directory. The unit restricts writes to `/var/lib/cbb-agent` and blocks privilege escalation and device access. The default unit therefore intentionally cannot perform privileged memory capture. Review any separately authorized service override rather than removing protections automatically.

`deploy/agent/agent.example.json` is a documented template; it does not contain real credentials and cannot be used as an enrolled collector. Installer scripts were reviewed and syntax-tested where available; actual service installation, privileged OS collection and cloud certificate enrollment must be validated on the target systems.
