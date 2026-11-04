# Windows integration audit · 4 November 2026

This acceptance run covers the Windows Virtual Mode deployment and supersedes the October runtime status in the earlier audit. It does not certify the Linux Cloud Mode environment. Original architecture documents describe the design; this file records what ran.

| Capability | Verified result | Boundary |
|---|---|---|
| Windows Firewall | Logging enabled on all three profiles. Six controlled outbound TCP attempts to `192.0.2.123` on ports 45101–45106 produced six actual DROP records. The temporary rule was removed. The application emitted `FW-PORT-BURST/1.0`. | A single drop has many possible causes. The burst rule uses a 60-second receipt window. Replaying older logs can trigger it. |
| Native Suricata | Official, signed OISF Windows 8.0.7 engine, running Npcap driver and active Wi-Fi interface. Configuration passed `suricata -T`. A harmless HTTP marker generated SID 9900001 in EVE, and its original bytes were preserved in the Windows application. | Packet visibility is limited to that adapter. Signature coverage depends on the active rule files. The shipped Windows profile uses nine vendor protocol rule families and three project signatures. Linux ET Open setup is a separate path. |
| Analyst workspace | The dedicated collector adds its sealed evidence to the owner's live endpoint case. Live monitor displays up to 100 recent authorized records, newest alert summaries, source status, and last refresh. Browser checks exercised pause and source selection with no JavaScript errors, HTTP 5xx or horizontal overflow at a 390-pixel viewport. | A five-second browser refresh is not an end-to-end latency guarantee. Batch collection, outages and queued work add delay. Other roles only see their authorized case evidence. |
| Local model | Installed Ollama 0.40.13 and `qwen2.5:0.5b`. The normal authenticated AI endpoint completed a six-record isolated case using `ollama-local/1.0`. Its output was saved as `UNREVIEWED`. | Analysis is a derived aid requiring analyst review. Case analysis uses up to 300 recent records and ranks up to 12 for the model. Valid citations do not establish the truth of a finding. |
| Evidence and report | The private supervisor report contains the six genuine firewall records and the genuine Suricata marker. All seven raw SHA-256 checks matched, and offline package verification returned `VALID`, `LOCAL_CHECK_ONLY`. An editable DOCX and PDF are included in the signed case export. | Verification relied on the local deployment key. An independently operated witness was not tested in this run. The source release excludes private evidence and signing material. |
| Regression | 44 Python tests passed with one upstream warning. Three frontend tests passed, as did TypeScript and the production build. | These are specific automated and live checks. Encrypted traffic, different adapters, large sustained loads, new signatures, OS updates and future log rotations can change results. |

## Audit changes

- Fixed a real collection stall caused by a malformed Windows Firewall record. Its complete original bytes now enter the normal sealing pipeline with a parse-quality flag. The next valid record can proceed.
- Sealed network indicators and multi-port firewall bursts now create alerts in the same database transaction as the corresponding evidence. Background correlation continues in bounded batches.
- Audited case intake and case-scoped live feeds retain authorization boundaries. Case analysis rechecks membership before saving the model response.
- Native installation, running adapter status, readable EVE and a matched marker are distinct checks. NIC checksum offload required a capture-profile adjustment. Seven checksum rules have a per-source rate limit recorded in the threshold configuration.
- Signed reports and cloud backup remain separate operations. Previously verified MEGA readback checks used controlled material. The private supervisor report stays local unless an administrator enables and requests backup.

The pre-existing WSL route still reports Windows servicing error 14098. Native Suricata on this laptop avoids that dependency. The server launcher can start the explicitly configured 15-minute Windows sensor. Use the walkthrough to renew the capture.
