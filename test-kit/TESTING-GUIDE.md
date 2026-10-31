# Cyber Black Box: step-by-step testing

Use your existing dashboard and administrator account. Keep the server window open. These tests use synthetic observations and files in a small lab folder. Synthetic imports test processing, not actual attack detection. Do not alter or delete files inside `data/archive`, `data/keys` or the database to test tampering; the automated tests use isolated temporary copies for that.

## 1. Create your test case

1. Click **Case workspace** in the left menu.
2. Click **New case**.
3. Case title: **My first feature test**.
4. Investigation scope: **Harmless synthetic data and local lab files only**.
5. Leave severity at Level 2. Click **Create case**.

Expected: the case opens and has no evidence yet.

## 2. Import six safe observations

1. Click **Collectors**, then **Import**.
2. Leave **Structured records** selected.
3. Destination case: **My first feature test**.
4. Import label: **Baby-step demo**.
5. Source type: **lab.fixture**. Record format: **jsonl**.
6. In **Upload a text file (optional)** choose `test-kit/01-safe-events.jsonl` from your project folder.
7. Click **Import and preserve records**.
8. Click **Evidence explorer** and refresh.

Expected: six new records beginning with **DEMO ONLY**. Their event timestamps are fixed sample dates; receipt time is the time you imported them. The offline import may appear OFFLINE in Collectors because it is not a running endpoint agent.

## 3. Search and inspect evidence

1. Search for **DEMO ONLY**.
2. Filter Source to **lab.fixture**.
3. Open one record. Review its ID, source, times, hashes, normalized fields and original bytes.
4. Clear the filter and confirm the records return.

Expected: the original bytes match the selected line in the test file. Inspecting or downloading bytes creates custody activity.

## 4. Check duplicate protection

Repeat step 2 using the SAME account, case, label, source, format and file. Do not change the label or file contents. Expected: evidence count stays the same; a repeat import does not create six more records. A different label or changed file is a new import identity and is not this duplicate test.

## 5. Check input validation

Repeat the import dialog using `03-invalid-json.txt`, source **lab.fixture**, format **jsonl**, and label **Invalid input test**. Expected: the application explains that record 1 is invalid/contains a duplicate JSON key. It must not add a sealed evidence record. An error during this intentional test is the expected result.

## 6. Timeline and alerts

Wait around 15 seconds for background analysis, then refresh.

1. Click **Timeline** → **Correlated incidents**.
2. Look for the sample process linked to the file/network observations. Click a linked evidence ID.
3. Switch to **Event timeline** and inspect the sample order.
4. Click **Alerts & anomalies**. The failed sign-in, simulated pattern match and log-clear observations should produce rule findings.
5. Click **Review** on one finding, choose **ACKNOWLEDGED**, and enter **Reviewed harmless demonstration data**. Save.

Expected: the finding status changes and its review appears in custody. This validates rule processing, not a real-world detection accuracy claim. Model results are a different tab and require a trained model.

## 7. Notes, versions and case workflow

1. Open **Case workspace** → **My first feature test**.
2. Confirm the six records are attached automatically.
3. Add an investigation note: **The imported records are synthetic. No real attack occurred.**
4. Revise your note if the revision control is shown; inspect the earlier version.
5. Edit the case and change status to **INVESTIGATING**.
6. Keep the retention hold enabled.

Later, test closing the case: enter a conclusion before selecting CLOSED. Closing without a conclusion must be rejected. Reopen it before further imports/acquisitions.

## 8. Signed checkpoints and verification

1. Click **Integrity & checkpoints**.
2. Click **Create checkpoint**.
3. Click **Run verification**.
4. Leave the optional trusted-checkpoint box empty and click **Queue verification**.
5. In **Background jobs**, wait for the verification job to reach COMPLETE.
6. Return to **Integrity & checkpoints** and open its result.

Expected: **VALID**, zero discrepancies, and **LOCAL_CHECK_ONLY** on the normal local installation. COMPLETE means the job finished; VALID is the actual integrity result. LOCAL_CHECK_ONLY is honest and expected until an independent witness is configured. Download a signed checkpoint to a separate location for later comparison.

## 9. Chain of custody

1. Click **Chain of custody**.
2. Load/refresh the entries. Administrators can inspect the global custody trail.
3. Look for import, evidence-sealing, case-note, review and verification actions.
4. Optionally copy your case ID into **Custody target ID** and click **Load custody trail**.

Expected: timestamped actions with actor and target identifiers. Case filtering is an exact target filter; evidence-targeted actions may require the evidence ID instead.

## 10. Export a report and verify it offline

1. Click **Reports & exports**.
2. Open the package-generation action, select your case and click **Generate package**.
3. Check **Background jobs** until the export is COMPLETE.
4. Return to Reports, refresh and download the ZIP.
5. Extract a COPY of the ZIP and open `report.html` in your browser. Inspect `manifest.json`, `checkpoint.json` and the `evidence` folder.

To verify the original ZIP, open PowerShell in the project folder and run the following. Replace only the example ZIP path with the downloaded file's actual full path:

```powershell
.\.venv\Scripts\python.exe -m cbb.cli verify-package "C:\Users\PC Tecnologies\Downloads\YOUR-DOWNLOADED-FILE.zip" --public-key "c79XfyakfVt6tdoI2TGU1cBNGGWQJeOefbtIA1Pdrfg="
```

That public key belongs to the current installation, as recorded during setup. If you initialize a different installation, use that installation's independently saved key. Expected: VALID, evidence_checked includes your selected records, failures is empty. Browser Print can save the readable report as PDF.

## 11. User roles and sharing

1. As administrator, open **Administration** and create a **reviewer** account with a unique password.
2. Open your test case and add that account as a case member.
3. Open an InPrivate/Incognito browser window and sign in as the reviewer. Keep your original admin window open.
4. Confirm the shared case is visible and a note can be added.
5. Confirm administrator actions such as creating users and enrolling collectors are unavailable or rejected.
6. Create an **investigator** account too; share the test case with it for the acquisition test below.

Expected: reviewer access is scoped to assigned cases. Investigators can search the evidence pool; administrator is not automatically entitled to every unrelated raw record.

## 12. Start a real, narrow Windows lab collector

This section reads only your selected lab folder plus the Windows System channel if you choose the `--enable-events` flag. No memory capture is enabled.

Open File Explorer in the project folder, type **powershell** in its address bar and press Enter. This opens a SECOND window. Leave the server window running. Run:

```powershell
New-Item -ItemType Directory -Force -Path .\test-kit\watched | Out-Null
```

In **Collectors**, click **Enroll collector**, enter **Windows lab test**, choose Windows and create the token. Copy it; it expires after ten minutes. In the new PowerShell window run these commands, replacing PASTE_NEW_TOKEN with that enrollment token (NOT your first-time setup token):

```powershell
$env:CBB_ENROLLMENT_TOKEN = 'PASTE_NEW_TOKEN'
.\.venv\Scripts\python.exe -m cbb.agent --config .\agent-data\lab-test.json enroll --server http://127.0.0.1:8765 --server-key "c79XfyakfVt6tdoI2TGU1cBNGGWQJeOefbtIA1Pdrfg=" --name "Windows lab test" --allow-path "C:\Users\PC Tecnologies\Documents\ChatGPT\cloud box\test-kit\watched" --yara-rules .\deploy\agent\lab-rules.yar --enable-events --enable-acquisitions
Remove-Item Env:CBB_ENROLLMENT_TOKEN
```

If you want file-only testing, omit `--enable-events`. If `lab-test.json` already exists, do not overwrite an existing identity; use its existing configuration and skip reenrollment.

In the dashboard, find **Windows lab test** → **Configure**. Allowed file paths must contain exactly:

```text
C:\Users\PC Tecnologies\Documents\ChatGPT\cloud box\test-kit\watched
```

Keep Windows event channels at **System**, poll interval 5 and save signed configuration. Now run:

```powershell
.\.venv\Scripts\python.exe -m cbb.agent --config .\agent-data\lab-test.json run
```

Keep this collector window open. Expected: the endpoint becomes ONLINE, with health and spool information. Inspect health for permission/source errors. A missing or unreadable Windows channel is not a successful collection test.

## 13. File changes, YARA and Windows events

1. Open `test-kit/watched` in File Explorer.
2. Create a text file called `marker.txt` using Notepad.
3. Put **CBB_TEST_MARKER** in it and save. This is a harmless string matched by the bundled lab rule.
4. Wait 15 seconds, then use the investigator account's **Evidence explorer** to filter **fim** and **yara**. Live observations are initially unassigned; the investigator can find them and add them to your case.
5. Edit the file, save again, then rename it. Check for new observations. The file hash should change when its content changes.
6. If Windows events were enabled, filter **windows.event** and inspect preserved System events. System logs may be quiet; inspect health before assuming a failure.

Expected: file observations and a real YARA match on the harmless marker. The imported synthetic YARA observation in step 2 was a separate processing test. Do not expect Security/Sysmon coverage unless those channels and their required auditing/permissions are configured.

## 14. Approved file acquisition

1. In the administrator session, go to **Acquisitions** and create a proposal.
2. Select your test case and **Windows lab test** collector.
3. Approved template: **Selected files**.
4. Absolute file paths: the full path to `test-kit/watched/marker.txt` (use its current name if you renamed it).
5. Maximum bytes: **1048576**. Time limit: **120** seconds.
6. Reason: **Collect my harmless marker file for the project test**. Submit.
7. In the separate investigator session (already a member of the case), open Acquisitions, inspect the plan and approve using that account's password.
8. Keep the collector running and refresh the job.

Expected: the approved job progresses to COMPLETE, a hash-verified artifact appears, and its metadata joins the case. The person who proposed it cannot approve their own request with default settings. Try that rejection before the other account approves if you want to test separation of duties. Do not choose memory capture for this beginner test.

## 15. Safe network parser test

Import `02-safe-network.jsonl` into your case, with source **suricata.eve**, format **jsonl**, label **Synthetic network test**. Expected: a network.alert record and a rule finding. This tests EVE normalization, not live network capture or the Suricata executable.

For the actual PCAP path, use an authorized PCAP from your lab, choose the Import dialog's **PCAP file** tab, preserve it, and inspect its analysis job. Without installed/configured Suricata the original file should be retained but analysis fails with TOOL_UNAVAILABLE/TOOL_CONFIGURATION. That is an expected dependency check, not a passed end-to-end Suricata test. Configure the tool as described in `docs/DEPLOYMENT.md`, then retry the failed job.

## 16. Model training and anomaly ranking

The six-record import is insufficient for meaningful training. The model requires at least 30 occupied five-minute asset windows and at least five later holdout windows. With one continuously active asset, plan roughly 2.5–3 hours or more, with observations in the windows. It uses SERVER RECEIPT TIME; changing timestamps inside a freshly imported file cannot fabricate that history.

1. Collect reviewed benign activity on a dedicated lab asset; keep synthetic suspicious fixtures out of its selected baseline.
2. In **Models & rules**, choose Train, enter the UTC interval covering that baseline and the lab asset ID, add a review note and confirm it is benign.
3. Check Background jobs. If INSUFFICIENT_BASELINE/HOLDOUT appears, collect more appropriate data and submit a new job.
4. Open the completed model's manifest and inspect its training/holdout counts and hash.
5. Collect a later interval. Choose Score with start at or after the baseline's end and end after that later data.
6. Inspect model findings in Alerts. A completed scoring job can legitimately produce zero alerts; do not invent anomaly detections.

For an immediate isolated implementation test, run `python -m pytest tests/test_features.py -q` using the project venv as shown below. Its synthetic training test is not a substitute for evaluating your own dataset.

## 17. Automated failure tests, restart and backup

In a second PowerShell window, in the project folder:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

These tests use temporary data, not your current dashboard database. They cover tampering, duplicate delivery, signing, authorization, uploads, parsing and model handling. Record the actual result. The build's recorded result was 29 passing Python tests and an upstream deprecation warning; tests are not a zero-defect guarantee.

For a manual restart test, stop the collector with Ctrl+C, stop the server with Ctrl+C, restart the normal launcher and sign in. Your case/evidence should remain. Start the collector with the SAME configuration and verify it reconnects. Do not delete its spool.

For a local backup test, stop both first, then run:

```powershell
.\.venv\Scripts\python.exe -m cbb.cli --data data backup backups/my-first-test
.\.venv\Scripts\python.exe -m cbb.cli --data restore-test restore backups/my-first-test
```

Both destination folders must be new. Expected: restore verification reports no failures. This restores into a separate directory and does not replace your live data. Restart the usual launcher afterward. Backups contain secrets and must remain private.

## 18. Features needing another environment

Linux journal collector: enroll/run on an authorized Linux machine, then verify actual journal observations and restart continuity. Follow `docs/AGENT_GUIDE.md`.

Cloud Mode/mTLS: deploy the Compose cloud profile on your Linux server, issue/bind individual collector certificates and prove that a missing/wrong certificate is rejected. Follow `docs/DEPLOYMENT.md`.

Independent witness: deploy the witness in a genuinely separate trust domain, pin its key, submit checkpoints from sequence 1, and confirm verified witness receipts. Same-laptop witnessing is only a functional demo.

S3 archive: configure a versioned Object Lock bucket and IAM, trigger archive replication in Administration, and inspect version IDs and readback verification. An unconfigured bucket is not a passed storage test.

Memory capture/Volatility: requires a compatible, approved tool, privileges and an authorized lab memory image. Use the collector guide and `python -m cbb.forensics --help`; do not experiment on your everyday laptop as part of this basic walkthrough.

Optional MFA: after the core workflow, click your account at the top, provide your password, generate a secret, add it to your authenticator and confirm the current code. Verify login in a separate browser before signing out everywhere. This revision does not provide a beginner self-service MFA recovery workflow.

For your FYP record, mark every test **PASS**, **FAIL**, or **NOT CONFIGURED/NOT TESTED**, with a screenshot and a short observation. Never mark an unavailable external integration as passed.
