# Windows par authentic Cyber Black Box demo

Tayyar kiya gaya: 30 October 2026. Yeh runbook actual files aur actual collector observations ke liye hai. Demo abhi tumhare live system par execute karke PASS declare nahi kiya gaya. Har result rehearsal mein khud verify karna hai.

## Scenario: research file ki tabdeeli aur evidence preservation

Story: laboratory ki research file mein authorized controlled tabdeeli hoti hai. Collector usay observe karta hai. Analyst file-change aur harmless YARA match review karta hai. Server ki temporary unavailability ke dauran collector delivery queue maintain karta hai. Doosra authorized user file acquisition approve karta hai. End par signed evidence report banti hai aur offline verifier usay check karta hai.

Yeh real file changes aur real collection ka experiment hai. Isay real attacker, malware incident ya automatic attack prevention kehna durust nahi. Imported fixture data is presentation ka live evidence nahi hoga.

## A. Pehle setup: 20–30 minute rehearsal

### A1. Teen windows samajh lo

1. **Server window:** Start-Cyber-Black-Box.cmd se khulne wali window. Isay running rakho.
2. **Collector window:** agent run command. Isay bhi running rakhna hai.
3. **Action window:** PowerShell jahan tum demo commands chalaoge.

Action window kholne ke liye File Explorer mein project folder kholo, address bar mein `powershell` likho aur Enter karo. Har command project root se chalegi:

```powershell
Set-Location -LiteralPath 'C:\Users\PC Tecnologies\Documents\ChatGPT\cloud box'
```

### A2. Harmless demo file banao

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-kit\Invoke-LiveDemo.ps1 -Step Prepare
```

Yeh sirf `test-kit/live-lab` ke andar naya run aur text file banata hai. Console mein watched-root path, file path, UTC time aur SHA-256 milenge. Purana run overwrite nahi hota. Nayi rehearsal ke liye `-Step Prepare -NewRun` use kar sakte ho.

### A3. Accounts aur case

Admin dashboard mein **Administration** se do alag investigator accounts banao: `analyst-demo` aur `approver-demo`. Apne strong passwords rakho. Case **Windows Live Investigation** admin account se banao aur dono investigators ko case member banao. Teen browser sessions use karo: admin normal browser, analyst InPrivate, approver doosra browser/profile. Kisi aur shakhs ki identity claim na karo: agar tum khud dono roles demonstrate kar rahe ho, supervisor ko batao ke yeh two-account workflow demonstration hai.

Live collector ki unassigned evidence analyst account search kar sakta hai. Admin ko automatically sab raw evidence nazar nahi aata. Analyst selected records ko shared case mein attach karega; phir admin ko bhi woh records nazar aayenge.

### A4. Dedicated collector enroll karo

Admin mein **Collectors → Enroll collector**: name **Supervisor Windows Lab**, OS **Windows**. Naya enrollment token copy karo. Yeh bootstrap/setup token se alag hai aur 10 minute mein expire hota hai.

Action window mein:

```powershell
$env:CBB_ENROLLMENT_TOKEN = Read-Host 'Naya collector enrollment token paste karo'
.\.venv\Scripts\python.exe -m cbb.agent --config .\agent-data\supervisor-lab\agent.json enroll --server http://127.0.0.1:8765 --server-key 'c79XfyakfVt6tdoI2TGU1cBNGGWQJeOefbtIA1Pdrfg=' --name 'Supervisor Windows Lab' --allow-path 'C:\Users\PC Tecnologies\Documents\ChatGPT\cloud box\test-kit\live-lab\watched' --yara-rules .\deploy\agent\lab-rules.yar --enable-events --enable-acquisitions
Remove-Item Env:CBB_ENROLLMENT_TOKEN
```

Public key is current installation ki saved key hai. Agar deployment dobara initialize hui ho to nayi trusted key use karo; mismatch ignore mat karo. Agar config pehle se maujood hai to reenroll mat karo: existing collector ko run karo. Is dedicated folder ko doosre collectors ke spool ke saath share mat karo.

Dashboard mein naye collector ka **Configure** kholo. Allowed file paths:

```text
C:\Users\PC Tecnologies\Documents\ChatGPT\cloud box\test-kit\live-lab\watched
```

Windows event channels, har line par aik:

```text
System
Application
```

Poll interval **5**, maximum file size default; **Apply signed configuration**. Collector details se Asset ID copy kar lo: aage isi asset ka filter use karna hai.

### A5. Collector chalao

Doosri PowerShell window project folder mein kholo:

```powershell
.\.venv\Scripts\python.exe -m cbb.agent --config .\agent-data\supervisor-lab\agent.json run
```

Collector ko ONLINE hone do, health inspect karo. Permission error, transport error ya unreadable channel ho to pehle resolve karo. Commands ka successful start actual evidence arrival ka substitute nahi.

## B. Supervisor ke samne 12–15 minute ka core demo

### B1. Introduction aur baseline — 1 minute

Bolo: **“Main ab imported sample ke bajaye is Windows machine par actual file change karunga. Collector original observations preserve karega. Dashboard se evidence review aur signed export tak poora workflow dikhaunga.”**

Collector ONLINE, scoped watched path aur asset ID dikhao. Analyst session mein Evidence explorer ka source **fim**, Asset ID apna collector, aur received-time range current run rakho. Pehli observation **file.baseline** ho sakti hai: current implementation har nayi file ko pehli martaba baseline ke taur par observe karti hai.

Demo script ka Status chalao:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-kit\Invoke-LiveDemo.ps1 -Step Status
```

Original bytes mein FIM JSON ka `sha256` compare karo. **Envelope ke raw_sha256 ko actual watched file ka hash na samajhna:** raw_sha256 FIM JSON observation ke bytes ka hash hai; JSON ke andar sha256 watched file ke content ka hash hai.

### B2. Actual file modification — 2 minute

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-kit\Invoke-LiveDemo.ps1 -Step Modify
```

Collector ko deliver karne do, phir Evidence explorer refresh karo. Source fim aur correct asset/time filter use karo. Raw JSON mein exact file path, action **modified**, previous_sha256 aur naya sha256 compare karo. Search box summary text dhoondta hai; sirf file name search par rely mat karo.

Expected: naya hash purane se mukhtalif; evidence ka file hash console se match. Seconds ka fixed guarantee mat do: polling, disk, Windows logs aur server load delay badal sakte hain. Apna measured delay record karo.

Bolo: **“Yeh file waqai change hui hai. Independent local hash aur preserved observation ka hash match kar raha hai.”**

### B3. Real YARA execution, harmless marker — 2 minute

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-kit\Invoke-LiveDemo.ps1 -Step Marker
```

Is se actual lab file mein `CBB_TEST_MARKER` likha jata hai. Source **yara** filter karo. Expected: rule **CBB_Lab_Marker**, file hash aur ruleset hash raw JSON mein; event type **file.yara_match**. Alerts mein corresponding rule finding review karke reason do: **Authorized harmless marker test; no malware conclusion.**

Bolo: **“YARA engine ne real file scan ki. Marker harmless hai; main isay virus detection accuracy ka proof nahi keh raha.”**

### B4. Optional actual Windows Event Log — 1–2 minute

Application/System ki actual XML observations kholo aur Windows Event Viewer mein same channel aur EventRecordID compare karo. Initial read latest 100 retained events la sakta hai; purani entry ko freshly generated event na kehna.

Agar fresh repeatable OS event chahiye, approved lab par **Run as administrator** PowerShell mein yeh command chala sakte ho:

```powershell
eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO CBB-Demo /D "Cyber Black Box approved live laboratory event"
```

Event Viewer → Windows Logs → Application mein source CBB-Demo aur message dekho. Phir source windows.event ke preserved original XML mein same event match karo. Yeh administrator-created genuine OS log event hai, security incident nahi. Security log clear mat karna. Microsoft reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate

### B5. Controlled server outage — 2 minute

Yeh step sirf rehearsal mein kamyab hone ke baad live presentation mein karo. Sirf **server window** mein Ctrl+C; collector running rehne do. Poore laptop ka internet band karne ki zaroorat nahi: local server bhi isi laptop par hai.

Action window:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-kit\Invoke-LiveDemo.ps1 -Step OfflineChange
```

Collector errors/backoff ko observe karo; queue inspect:

```powershell
.\.venv\Scripts\python.exe -m cbb.agent --config .\agent-data\supervisor-lab\agent.json status
```

Queue mein observation aane tak wait karo. Retry backoff ki wajah se waqt lag sakta hai. Phir normal launcher se server restart karo, browser refresh karo, reconnect hone do. Expected: isi file ki offline change observation server par preserved ho, raw bytes sealed hone ke baad local pending queue drain ho. Compare collection and receipt times. Rapid modifications ke har intermediate version ko capture karne ka claim mat karo; test mein aik controlled change aur uski observation wait karo.

Bolo: **“Server unavailable tha. Collector ne is controlled observation ko locally queue kiya aur reconnect par deliver kiya.”** Sirf successful measured trial ke liye yeh claim karo.

### B6. Case investigation aur approved acquisition — 2 minute

Analyst se relevant FIM/YARA/Windows records **Windows Live Investigation** case mein add karo. Note likho: action, time, evidence IDs aur comparison result. Retention hold enabled rakho.

Analyst session mein **Acquisitions**: case select, Supervisor Windows Lab select, **Selected files** template, Status command wala exact current file path, maximum bytes **1048576**, timeout **120**, reason **Preserve the authorized live laboratory file after observed changes**.

Default setting mein isi proposer ka approve attempt reject hona chahiye. Doosre **approver-demo** session se plan review karke us account ke password se approve karo. Collector ko COMPLETE tak pahunchne do. Artifact download karo. File acquisition artifact ZIP hota hai, jisme collected file aur manifest ho sakte hain; agar download extension .bin ho to copy ko .zip naam de kar inspect karo. Extracted research-notes.txt ka Get-FileHash current original se compare karo; comparison ke darmiyan original file edit mat karo.

Bolo: **“System arbitrary command run nahi kar raha. Sirf approved template aur allowlisted file collect hui, aur server ne uploaded artifact ka digest verify kiya.”**

Optional separate acquisitions **Process snapshot** aur **Network connection snapshot** se us waqt ki psutil observations dikha sakte ho. Yeh sampled current state hai; historical process/network completeness ya packet capture nahi.

### B7. Integrity, custody aur report — 2 minute

Admin session: **Integrity & checkpoints → Create checkpoint → Run verification → Queue verification**. Job COMPLETE ke baad actual result dekho. Expected VALID, zero failures, LOCAL_CHECK_ONLY unless an independently administered witness is configured.

Custody mein note, review, proposal, approval, artifact registration, verification aur export actions dikhao. Kuch actions case-targeted aur kuch evidence/job-targeted hain, is liye zaroorat par global admin custody view use karo.

Reports & exports se case package generate/download karo. Readable report mein analyst conclusion **Controlled authorized laboratory experiment; no claim of real malware or attacker attribution** likho. Original ZIP offline verify karo (downloaded path replace karo):

```powershell
.\.venv\Scripts\python.exe -m cbb.cli verify-package 'C:\Users\PC Tecnologies\Downloads\ACTUAL-PACKAGE.zip' --public-key 'c79XfyakfVt6tdoI2TGU1cBNGGWQJeOefbtIA1Pdrfg='
```

Expected VALID. Privately save public key/checkpoint independently. Demo ke dauran live data/archive mein files change mat karo.

## C. Tampering ka safe proof

Live archive ko corrupt karne ke bajaye isolated temporary-data tests chalao:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_core.py -q -k 'tamper or tail_loss or offline_verifier'
```

Supervisor ko test source mein altered bytes / removed record / modified package wali action dikhao aur passing assertion explain karo. Bolo: **“Yeh isolated tamper-detection test hai. Meri actual investigation database ko damage nahi kiya gaya.”** Real compromise ya independent penetration test ka claim mat karo.

## D. Tamam features ka honest scope

| Feature | Windows par real demonstration |
|---|---|
| Gateway/normalization | Agent se actual observation, receipt aur sealed normalized/raw record |
| Windows collector | Actual readable channels; Event Viewer se XML identity match |
| FIM/YARA | Real file edits aur harmless pattern scan, console hash comparison |
| Evidence store | Local files/database; restart aur separate restore test |
| Integrity/custody | Actual signatures, chain checks, access/approval history |
| Cases/reports | Actual case notes, membership, report and offline verification |
| Acquisition | Approved selected file; optional bounded process/network snapshots |
| Timeline | Actual received observations; actual correlation tab needs suitable process+file/network source data |
| Correlation with strong identity | Optional configured Sysmon events 1/3/11 and ProcessGuid. FIM-only data se strong process relationship invent nahi karna |
| Anomaly model | Pehle se collected reviewed benign dataset + later scoring interval; single fresh import sufficient nahi |
| Network parsing | Actual authorized PCAP + configured Suricata, ya actual sensor EVE output; synthetic import ko live sensor mat kehna |
| Linux/cloud/mTLS/S3 | Extra system/service configuration; Windows-only demonstration se verified nahi |

Sysmon optional extension: install/configure only on an approved lab system, enable required events and its readable Operational channel, add that channel to collector configuration, then run a harmless process that creates a lab file. Match preserved ProcessGuid across actual OS records before claiming strong correlation. Installing Sysmon alone does not guarantee every source category is enabled. Official references: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon and https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events

Model rehearsal: collect at least 30 occupied five-minute asset windows with sufficient chronological holdout (at least five later windows). A single continuously active asset generally needs roughly 2.5–3 hours or more. These are SERVER RECEIPT-TIME windows; fake occurrence dates inside an import do not make real history. Choose a clean asset/range, document benign review, train, then score a later interval. Do not contaminate benign baseline with marker experiments. Zero alerts may be valid; report actual results, false positives and limitations.

## E. Evidence sheet aur latency measurement

Use `LIVE-RESULTS.csv`. Har row mein run ID, action UTC, first dashboard-visible UTC, evidence IDs, expected/actual result aur screenshot filename likho. Script ke local action records `live-lab/operator-observations.jsonl` mein hain; woh operator ground truth hai, server-signed evidence nahi.

1. Action time = script ka action_utc.
2. Collection time = preserved envelope ka collected_at.
3. Receipt time = server received_at.
4. Visible time = tumne dashboard par pehli martaba result dekha; manually record karo.
5. Action-to-visible latency = visible time minus action time; dashboard refresh bhi is measurement mein included hai.

Teen ya zyada controlled runs lo. Missed/late observations aur errors bhi count karo. “Zero loss” sirf apne finite test scope aur measured numbers ke saath likho; permanent guarantee nahi. Original sample imports aur aaj ke live records ko same evidence set mein confuse mat karo.

## F. Supervisor ke common sawal

**Kya yeh real hai?** File/OS activity aur collector output real hain. Scenario authorized aur controlled hai; attacker ya malware hone ka claim nahi.

**Kya yeh antivirus hai?** Nahi. Monitoring, preservation aur investigation system hai; automatic blocking/remediation implemented nahi.

**Kya evidence unchangeable hai?** Ordinary edits detect karne ke liye hashes/chains/checkpoints hain. Same-host administrator aur key compromise risks rehte hain; independent witness/retention stronger deployment controls hain.

**Kya har event capture hota hai?** Nahi. Coverage enabled sources, permissions, polling, OS retention aur resource limits par depend karti hai. Health aur gaps report karte hain.

**AI kya karti hai?** Reviewed baseline ke muqable mein unusual windows rank karti hai. Score attack probability nahi. Analyst final interpretation karta hai.

**Cloud live hai?** Sirf tab haan bolo jab actual deployed server/bucket aur successful authenticated transfer/verification dikha sako. Warna Windows Virtual Mode completed demonstration aur cloud acceptance pending batao.

Closing sentence: **“Is controlled experiment mein humne actual observation ko collection se preserved evidence, authorized acquisition aur independently rerunnable package verification tak trace kiya. Jo tests run nahi huay, unhein humne NOT TESTED mark kiya hai.”**
