# Notable log / rule context (redacted)

Append short entries when you see a useful `_raw` or a rule that taught a field lesson. **No secrets, no real hostnames/users/SIDs.**

---

### 2026-10-06 — Encoded PowerShell (Security 4688 XML)

- **Family:** xml_wineventlog_security
- **Sourcetype observed:** `XmlWinEventLog:Security` (source `WinEventLog:Security`)
- **EventCode:** 4688
- **Lesson:** `NewProcessName` = powershell path; `CommandLine` contains `-EncodedCommand` + base64. Rules that only filter Sysmon `Image` early miss this.
- **Rules touched:** DAC-WIN-0107 (fixed to include `` `windows_security` `` + coalesce)

### 2026-10-06 — Certutil encode (Security 4688 XML)

- **Family:** xml_wineventlog_security (+ xml_sysmon)
- **Lesson:** Exact event via `` `windows_security` `` + `NewProcessName=*certutil.exe` + `-encode`. Classic-only `WinEventLog:Security` returned 0. Cmdline-only `match(cmd,"certutil\.exe.*-encode")` can FP on search tooling.
- **Rules touched:** DAC-WIN-0041 (fixed to macro + proc AND flags)

### 2026-10-07 — CloudTrail privilege/compute chain (reference query)

- **Family:** aws_cloudtrail
- **Fields noted:** `eventName`, `userIdentity.arn`, `requestParameters.roleArn`, `requestParameters.functionName`, `responseElements.functionArn`, EC2 instance set path
- **Lesson:** Drop `index=cloudtrail` for portable DaC; store field paths in `sourcetypes/aws_cloudtrail.md`; prefer correlation over alerting every `RunInstances`/`PassRole`.
