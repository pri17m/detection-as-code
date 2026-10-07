# Log family: Sysmon Operational (XML)

## Sourcetype permutations

| Candidate | Notes |
|-----------|--------|
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Preferred |
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | Classic render |
| `XmlWinEventLog` + source containing Sysmon/Operational | Collapsed TA |
| `sysmon` / `sysmon:*` | Legacy |

**Macro:** `` `windows_sysmon` ``.

## Fields (EventCode=1 process create)

| Field | Confidence | Notes |
|-------|------------|-------|
| `EventCode` | high | 1 = Process Create |
| `Image` | high | Full path |
| `CommandLine` | high | |
| `ParentImage` / `ParentCommandLine` | high | Version-dependent richness |
| `User` | high | |
| `ProcessGuid` / `ProcessId` | high | |
| `Hashes` | medium | Config-dependent |

## Last updated

- 2026-10-06 — lab Sysmon process-create-only config
