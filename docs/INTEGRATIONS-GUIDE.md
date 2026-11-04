# Genuine tools and end-to-end demonstration

**4 November 2026 update.** See [Windows live acceptance](LIVE-ACCEPTANCE.md) and [Windows demo steps](WINDOWS-LIVE-DEMO.md) for current native Suricata, firewall and Ollama results. Earlier installation observations below are historical.

Updated 30 October 2026. Source and built dashboard live in:
`C:\Users\PC Tecnologies\Documents\ChatGPT\cloud box`

This guide supplements the original architecture and all twelve module mappings in README.md. There are two deployment profiles, Windows Virtual Mode and Linux Cloud Mode. No hardware profile is required.

## What is implemented and what still needs environment setup

| Component | Implemented behavior | Environment prerequisite |
|---|---|---|
| Suricata | Real executable/config test, bounded live Linux capture, EVE tailing with durable offsets, offline PCAP adapter, health and alerts | Ubuntu/WSL reboot/setup or a Linux sensor; appropriate network visibility |
| MEGA | Official MEGAcmd transfer; whole-file SHA-256 readback; signed inventory; manual/automatic jobs; staged restore check | User signs in locally to MEGAcmd; account quota/network available |
| Local statistical AI | TF-IDF relevance, MiniBatchKMeans grouping, evidence citations, analyst review, report inclusion | Installed scikit-learn; case with 1–300 records |
| Optional local LLM | Real Ollama structured-output API, schema/citation validation, local-only endpoint | Separately installed Ollama and local model; sufficient RAM |
| Isolation Forest | Reviewed baseline, chronological holdout, model hashes, anomaly scores | Enough baseline windows; evaluation on independent scenarios |
| YARA/FIM/events | Real yara-python, watchdog, hashing, Windows Event Log/journal collection | Collector capabilities enabled, allowed paths/channels and OS permissions |
| Zeek | Tails genuine external logs | Separately deployed Zeek sensor; not installed by this revision |
| Volatility/memory | Allowlisted, bounded external adapters | Operator-supplied hash-pinned tools, image and authorization; not installed here |
| Case reporting | PDF, editable DOCX, HTML, original bytes/artifacts, proof, notes, scoped custody and AI snapshot inside signed ZIP | ReportLab/python-docx installed |

Installed is not the same as running, capturing, or verified. Tools & sensors exposes actual server probes plus collector-reported input status. WSL tools run separately from the Windows server and therefore do not appear as Windows-installed Suricata. Input paths, heartbeat timestamps and fresh sensor status identify the collector side.

## Restart the updated application

Save your current work. In the terminal running Cyber Black Box press Ctrl+C, wait for it to stop, then run `Start-Cyber-Black-Box.cmd` from the project folder. Sign in with your existing account and refresh the browser. Do not initialize a new demo over your real data. The existing database is extended with cloud_objects and ai_runs tables at startup; existing accounts/evidence remain in place.

For a newly extracted copy: run `powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1 -Install`. Dependencies are pinned in requirements.lock. The release contains web/dist, so Node is needed only when editing/rebuilding the UI.

## MEGA login: baby steps

1. Open ordinary Windows PowerShell under the same account used to run Cyber Black Box.
2. Paste:

   ```powershell
   & "$env:LOCALAPPDATA\MEGAcmd\MEGAcmdShell.exe"
   ```

3. In the new `MEGA CMD>` prompt enter `login your-email@example.com`, replacing the example email.
4. Enter your password at its separate password prompt; enter authenticator code if requested. Never paste your password, recovery key or session ID into this application or chat.
5. Enter `whoami` to confirm the signed-in account. Keep the MEGAcmd background service available; do not run `logout` while backup jobs are running.
6. In Cyber Black Box open **Tools & sensors → Check tools**. MEGA should show installed/version and `SIGNED_IN`. A failed probe can mean the service, account, network or local IPC is unavailable; it is not evidence of a completed backup.
7. Open **Cloud archive**. Enable MEGA, keep scheduling **Manual only** for the first test, and save. Default folder is `/CyberBlackBox`.
8. Select **Back up now**. Watch the job until COMPLETE. Then inspect Cloud archive → Verified objects. A queued job is not a verified copy.
9. Select **Restore check** on an object. A completed check places bytes under `data/restore-staging/<unique-id>/`; compare the reported SHA-256. Original evidence is not overwritten.
10. Enable automatic scheduling after your initial backup/restore succeeds. Minimum interval is 5 minutes. Account quota, connectivity and available local disk can delay or fail transfers; jobs show errors/retries.

The server invokes the official executable with argument arrays, without a command shell. Windows defaults to `%LOCALAPPDATA%\MEGAcmd\MegaClient.exe`; override its directory with `CBB_MEGACMD_DIR` when necessary. Linux uses installed `mega-*` commands under the same service user/session. Credentials are managed by MEGAcmd, not copied into application settings.

Backup includes closed raw segments, their canonical-envelope manifests, acquisition/PCAP artifacts, case-report packages, signed checkpoints, and a snapshot of cases, links, notes, custody, assets and AI outputs. The signed inventory records hashes and remote paths. New bytes arriving after the snapshot are covered by later runs. Previously verified objects are not downloaded on every run; timestamps show the last check, and Restore check explicitly rechecks them.

MEGA is not WORM storage. A cloud-account holder can alter/delete backups. Keep the verification public key separately and protect signing keys. The MEGA archive deliberately excludes private keys, collector credentials, login records and the live database. It is an evidence archive, not a complete application restore. Use the existing offline `cbb backup` / `restore` workflow (or PostgreSQL procedures in DEPLOYMENT.md) for consistent database/key recovery. Do not synchronize deletion of evidence to the remote folder.

## Suricata after the approved WSL installation

The Windows installer reported a required reboot. This revision does not restart Windows automatically and does not claim a working Suricata capture before that reboot.

1. Save work and restart Windows manually.
2. Open PowerShell and run `wsl --list --verbose`. If Ubuntu is absent, run `wsl --install -d Ubuntu` (approve Windows elevation if requested). Start Ubuntu and complete its first username/password prompts.
3. In PowerShell:

   ```powershell
   Set-Location -LiteralPath 'C:\Users\PC Tecnologies\Documents\ChatGPT\cloud box'
   powershell -ExecutionPolicy Bypass -File .\scripts\setup-suricata-wsl.ps1
   ```

   The script installs Ubuntu's real Suricata package, configures EVE output, disables the distribution's default unattended capture service and runs `suricata -T`. It stops on setup failure. It does not replace Windows.
4. Start the Cyber Black Box server. In its Collectors page create an enrollment token for a dedicated **WSL network sensor**. Copy the deployment public key from a separately trusted setup record.
5. Enroll a Windows collector which reads the WSL-produced EVE file from the shared project folder:

   ```powershell
   $env:CBB_ENROLLMENT_TOKEN = Read-Host 'Paste the short-lived enrollment token'
   $trustedServerKey = Read-Host 'Paste the trusted server public key'
   .\.venv\Scripts\python.exe -m cbb.agent --config sensor-agent-data/agent.json enroll --server http://127.0.0.1:8765 --server-key $trustedServerKey --name 'WSL Suricata sensor' --eve-file 'C:\Users\PC Tecnologies\Documents\ChatGPT\cloud box\sensor-data\eve.json'
   Remove-Item Env:CBB_ENROLLMENT_TOKEN
   .\.venv\Scripts\python.exe -m cbb.agent --config sensor-agent-data/agent.json run
   ```

   Use a new unused collector config folder; do not overwrite an existing collector's credentials. The collector may initially report a missing EVE file until capture starts.
6. In another PowerShell window inspect available Linux interfaces with `wsl -d Ubuntu -- ip -brief link`, then start a bounded authorized capture, for example:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\start-suricata-wsl.ps1 -Interface eth0 -Seconds 900 -MaxMiB 256
   ```

   The process ends after 15 minutes, operator interruption, an error or the output budget. The disk budget is checked every two seconds and can overshoot under high traffic. Existing output counts toward that budget; preserve/move it through your evidence process before another session. Do not delete an EVE file the collector has not drained. The status file records the actual version, interface, config/rule hashes, process and stop reason. A stale RUNNING status is not shown as fresh liveness. After an abrupt crash, inspect the PID in `sensor.lock` before removing a stale lock.
7. Generate harmless real HTTP traffic *inside Ubuntu* while capture is running:

   ```powershell
   wsl -d Ubuntu -- curl --max-time 15 http://example.com/cbb-supervisor-demo
   ```

   The supplied rule matches the request URI regardless of the HTTP response status. DNS/network availability is required. This is a pipeline marker, not malware or a production detection rule set. Use it only on a network you are authorized to monitor.
8. Open **Tools & sensors**: confirm recent collector heartbeat, readable EVE and fresh RUNNING sensor status. Open **Evidence explorer**, filter source `suricata.eve`, find `CBB authorized HTTP pipeline marker`, and inspect original bytes/flow information. Add that evidence to the supervisor case using an investigator account.
9. Stop capture; let the collector drain its queue; confirm SEALED receipts. Create/check a checkpoint, generate the case report and verify its ZIP offline. Record actual latency, queue size, dropped packet statistics from EVE stats, and any failures.

WSL `eth0` sees traffic on that Linux interface. It does not automatically capture all Windows applications, Wi-Fi traffic, other LAN devices or decrypted HTTPS contents. To demonstrate Windows endpoint activity, use the genuine Windows Event Log/FIM collector alongside the WSL sensor. To monitor another network, deploy a Linux sensor with explicitly authorized interface/SPAN/TAP visibility and document that scope.

The included marker rule is intentionally narrow. A production threat rule feed, tuning, update policy and false-positive evaluation are additional acceptance work. Supply a reviewed rule file to `run_sensor.py --rules` for such experiments; do not describe the marker-only demo as a complete IDS deployment.

## AI and reporting demonstration

1. Add real captured evidence to an assigned case. Keep synthetic examples clearly labelled and in a different case/database.
2. Open **Evidence assistant**, select the case, keep **Local statistical** and enter an investigation question. Queue the job.
3. Review the extractive observations and linked evidence. The displayed similarities are text relevance, not attack probabilities. Grouping does not prove causation.
4. Record ACCEPTED, REJECTED or NEEDS_REVIEW and your reason. Review decisions append to the custody ledger; the latest decision is also indexed beside the unchanged output. Input/output hashes and citations are retained.
5. Generate a new report from the case. Download its signed ZIP in Reports & exports. It contains report.docx, report.pdf, report.html, case.json, notes.json, custody.json, ai-assistance.json, raw evidence/artifacts, manifest, proof and signed checkpoint.
6. Verify the original ZIP with `python -m cbb.cli verify-package <package.zip> --public-key <trusted-key>`. Editing the Word file creates a derivative; it does not update the original signed package. Reports distinguish captured observations, analyst conclusions and AI advice. Unrepresentable XML control characters are replaced only in human-readable rendering; original bytes/JSON remain preserved.

Default AI stays local and does not download a large model. This laptop had about 8 GiB RAM with limited free memory during setup. Optional Ollama is an explicitly separate capability: install Ollama, download an appropriately sized local model following vendor guidance, set `CBB_OLLAMA_MODEL` to its installed model name before starting the server, and select Optional local LLM. The default endpoint is `http://127.0.0.1:11434`; only loopback endpoints are accepted. No cloud model names or remote model metadata are accepted. Requests are bounded to twelve relevant observations, a 48,000-character context ceiling, 4,096 model context tokens and 1,200 generated tokens; insufficient context/output/schema returns a visible failure. LLM accuracy and RAM fit must be measured locally. It cannot execute commands, change evidence or approve forensic acquisition.

## Operational budgets and error behavior

- Collector polling defaults to five seconds plus jitter, with at most 100 log lines per source/cycle. Durable delivery, queue state and explicit gaps matter more than a “real time” badge.
- Sealing/rule jobs, long-running report/AI/transfer jobs, and checkpoint scheduling run in separate threads of the single application process. This is not a distributed queue; SQLite transactions and checkpoint work can still cause contention.
- Transfers are sequential, with a ten-minute per-command timeout and up to three job attempts. MEGA may continue a transfer after client timeout; content-addressed object paths and readback verification control retries. Restore mismatches are retained as untrusted staged files and marked MISMATCH.
- Large archives require bandwidth, download quota and spare disk at least the largest object plus a 50 MiB reserve. Automatic metadata snapshots and staged recovery files consume additional disk; monitor it. No automatic evidence deletion is enabled.
- Shutdown is bounded. An interrupted running job is recovered on next startup; a crash after an external side effect can leave an extra remote version or a duplicate derived report/analysis. Compare IDs and custody history; exactly-once external side effects are not promised.
- Low-risk acceptance: genuine marker appears in sealed evidence; observed latency/gaps/drop counters documented; corrupt readback fails; unauthorized case access is denied; AI citations are scoped; offline report verification succeeds. Detection false positives/negatives and availability failures remain possible.

## Official references

- [Suricata installation](https://docs.suricata.io/en/latest/install.html) and [command options](https://docs.suricata.io/en/latest/command-line-options.html).
- [MEGAcmd guide](https://github.com/meganz/MEGAcmd/blob/master/UserGuide.md).
- [Ollama local chat API](https://docs.ollama.com/api/chat) and [structured output](https://docs.ollama.com/capabilities/structured-outputs).
