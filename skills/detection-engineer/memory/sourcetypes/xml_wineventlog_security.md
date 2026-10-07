# Log family: Windows Security (XML / classic)

## Sourcetype permutations

| Candidate | Notes |
|-----------|--------|
| `XmlWinEventLog:Security` | Lab-proven; TA XML |
| `WinEventLog:Security` | Classic compound |
| `XmlWinEventLog` + `source=XmlWinEventLog:Security` or `source=WinEventLog:Security` | TA ≥5 collapsed |
| `WinEventLog` + `source=WinEventLog:Security` | Collapsed classic |

**Macro:** `` `windows_security` `` (preferred in DaC).

Lab observation: `sourcetype=XmlWinEventLog:Security` with `source=WinEventLog:Security`.

## Fields (4688 process creation)

| Field | Confidence | Notes |
|-------|------------|-------|
| `EventCode` / `EventID` | high | Use EventCode in SPL when TA maps it |
| `CommandLine` | high | Needs ProcessCreationIncludeCmdLine |
| `NewProcessName` | high | 4688 process path |
| `ParentProcessName` / Creator fields | high | Parent |
| `SubjectUserName` / `SubjectDomainName` | high | Creator subject |
| `SubjectUserSid` | high | Redact in samples |
| `NewProcessId` / `ProcessId` | high | Hex in raw XML |
| `TokenElevationType` | medium | UAC token type |
| `Image` | low on pure 4688 | Prefer coalesce with NewProcessName |

## Lab-proven technique tokens

- PowerShell: `CommandLine` contains `-EncodedCommand` / `-enc`
- Certutil: `NewProcessName` ends with `certutil.exe` AND `CommandLine` has `-encode` / `-urlcache` / `-decode`

## Last updated

- 2026-10-06/07 — Windows event-log lab (DAC-WIN-0107, DAC-WIN-0041)
