# Build validation — 29 October 2026

Executed in the Windows project workspace:

| Check | Result |
| --- | --- |
| Python automated suite | 29 passed, 1 upstream Starlette/HTTPX deprecation warning |
| TypeScript compilation | Passed |
| Vite production build | Passed; built assets included in web/dist |
| Interface unit tests | 3 passed |
| Headless Edge browser walkthrough | Login and all 13 navigation screens opened; no page JavaScript errors |
| Desktop and narrow-screen rendering | Screenshots generated and inspected; responsive spacing corrected |
| Synthetic evidence verification | Six fixture observations, VALID / LOCAL_CHECK_ONLY |
| Offline SQLite backup and restore | Restored into a separate directory; six observations verified without failures |
| Offline signed package verification | Tested against pinned public key; modified package rejected |

The Python suite covers receipt idempotency/conflicts, malformed records, raw/manifest tampering, tail loss against a checkpoint, immutable rows, signing-key mismatch, export snapshot preservation, case scope, CSRF/origin enforcement, revocation, acquisition approvals/uploads, model training/scoring, file monitoring/YARA, signer/witness behavior and PCAP preservation when its optional parser is missing. A Windows fsync issue discovered by the suite was repaired before the passing run.

The browser walkthrough checks navigation and runtime rendering, not every possible form combination. Backend tests cover critical mutations. The optional Volatility command was checked for import/CLI startup only; no actual memory image analysis was performed.

No Docker, Linux cloud, live PostgreSQL, real S3 retention, external TLS certificate infrastructure, privileged memory capture, sustained workload benchmark or independent penetration test was executed here. CI configuration is supplied but has not run on a hosted CI account. Full platform acceptance remains necessary; passing local tests is not a zero-defect guarantee.

## Integration revision — 30 October 2026

The existing 29 tests plus seven integration tests passed as a 36-test suite. After a genuine Windows MEGAcmd output-handling issue was identified and fixed, the nine integration/regression tests passed (including bounded inherited-service-output and timeout behavior). TypeScript compilation, Vite build and three frontend tests passed. Browser automation opened all sixteen screens, completed local AI analysis/review and exported a signed report without JavaScript errors or HTTP 5xx responses; mobile width 390 px did not overflow. The six-record synthetic report verified offline as VALID / LOCAL_CHECK_ONLY, with four readable PDF pages.

Real MEGA transfer and the complete archive/staged-restore adapter passed against a separate labelled synthetic acceptance dataset. See mega-live-check.json and mega-live-archive-check.json. This does not establish capture completeness, real malware detection, external witness assurance or full application disaster recovery. Suricata/WSL live acceptance follows installation/reboot and is separately reported. See UPGRADE-AUDIT.md for findings and remaining limits.

Final regression after the vendor-process fix: **38 Python tests passed**, one upstream Starlette/httpx deprecation warning, in 20.50 seconds. Final TypeScript/Vite build passed; four changed screens were recaptured without page errors. WSL installation was retried after checking distributions; it again returned success with a required Windows reboot, and no Ubuntu distribution/capture was verified.
