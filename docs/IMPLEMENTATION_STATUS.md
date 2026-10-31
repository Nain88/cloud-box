# Implementation status and acceptance

All twelve proposal modules have executable implementation paths. This is not a claim that every architectural stretch feature, operating-system configuration or external product is installed and certified.

## Scope and proposal traceability

The source proposal is `source/CYBER_BLACK_BOX (1).pdf`, physical pages 10–12 for the twelve modules and page 13 for deliverables. The detailed revised specification is in `output/Cyber_Black_Box_FYP_Architecture.docx` and PDF. The README maps M01–M12 to source components. Hardware/TAP/Raspberry Pi requirements are excluded in this revision; network coverage comes from authorized software-visible sources or supplied files.

## Implemented safeguards

Durable receipt acknowledgement precedes sealing. Duplicate keys with altered content conflict. Raw bytes are kept separately from projections. Immutable-table triggers deter normal application edits; they do not constrain a database administrator. Hash chains, manifest digests, pinned signatures, independent witness receipts and offline verification provide different levels of evidence about alteration. UI assurance labels distinguish local checks from external anchoring. Case access, CSRF, origin checks, password hashing, MFA, constrained acquisition templates and explicit tool failures are implemented.

Acquisitions require operator authorization and endpoint-local allowlists. Memory acquisition only runs an explicitly configured, hash-pinned supported utility; no utility is downloaded or silently selected. All tests use benign fixtures. No real endpoint memory or sensitive system logs were collected while building the project.

## Known limitations and required environment acceptance

* Docker and a Linux/PostgreSQL server are not available in this Windows session. Compose files are supplied; live cloud startup, mTLS and PostgreSQL recovery still require testing on the destination system.
* Real Windows Security/Sysmon channels, Linux journald access, cloud traffic visibility and privileged memory capture depend on local permissions and tools. Unit tests cannot establish their capture completeness.
* Suricata PCAP processing, S3 Object Lock and Volatility require configured external tools/services. Missing dependencies return actionable errors. Their live integration acceptance requires operator-provided fixtures and credentials.
* The current anomaly model uses bounded counts in five-minute windows of server receipt time with chronological training/holdout separation. It does not implement every proposed rarity feature or prove detection efficacy. Evaluate on independent labelled runs; report false positives and missed detections.
* Correlation uses bounded process-to-file/network rules and analyst regrouping. It is a candidate relationship, not causal proof. Complex event-time watermark processing and distributed execution are outside this implementation.
* Reports now export signed ZIP packages with native PDF, editable DOCX, HTML, raw bytes/artifacts, JSON proof, scoped custody, notes and frozen AI analysis/review. Editing a DOCX creates an unsigned derivative.
* Storage retention is conservative: case holds and archive replication exist, but automatic evidence deletion/disposition is intentionally not exposed. Index rebuilding, general database migrations and automatic signer-failure reconciliation need separate operational work.
* Local secrets require disk encryption and OS access controls. A compromised endpoint can send misleading observations; a compromised server and signing key can forge new signed data. An independent witness limits retrospective changes but does not make the unanchored tail trustworthy.

## Acceptance gates

FYP-I: demonstrate import/collector receipt → sealed evidence → searchable case → checkpoint → offline-verified report, including malformed data, retries, tampering and restart tests. FYP-II: validate both operating systems, real mTLS, external witnessing, Object Lock, approved acquisition recovery, model evaluation and a measured workload/restore exercise.

Pass only when the actual run meets its stated budget and retains explicit failure counts. Suggested lab target: 20 events/s per collector with no acknowledged event loss under a controlled outage/restart experiment; measure latency and disk use rather than assuming the target. Allow nonzero detection error and document false-positive/false-negative results. No zero-error, zero-risk, forensic-admissibility or production-readiness guarantee is made.

See `VALIDATION.md` for the test outcomes from this build.

## Integration upgrade — 30 October 2026

MEGA archival/readback/staged restore, local evidence assistance, optional local Ollama, three GUI pages and bounded Suricata WSL scripts have been added. See INTEGRATIONS-GUIDE.md and UPGRADE-AUDIT.md for exact scope, environment prerequisites and acceptance status. MEGA login, genuine archive upload/readback and staged report restoration passed using isolated synthetic test data. WSL still requires a Windows reboot and subsequent genuine capture acceptance.
