# Windows telemetry contract (Splunk)

This document defines the **authoritative Splunk telemetry contract** for Windows detections in this repo:

- **Allowed sourcetypes** (org-portable; no `index=` hardcoding)
- **Required macros** for detections (preferred over explicit sourcetypes)
- **Minimum required fields** per key Windows / Sysmon Event IDs for Phase‑1 analytics

## Allowed sourcetypes

All detection metadata `sourcetypes[]` **must** be drawn from `config/sourcetype_map.yaml` → `allowed_sourcetypes` / `canonical`.

Minimum allowlist (must be present):

- `WinEventLog:Security`
- `XmlWinEventLog:Security`
- `WinEventLog`
- `XmlWinEventLog`
- `WinEventLog:System`
- `XmlWinEventLog:System`
- `WinEventLog:Microsoft-Windows-PowerShell/Operational`
- `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`
- `WinEventLog:Windows PowerShell`
- `XmlWinEventLog:Windows PowerShell`
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- `sysmon`
- `sysmon:*`

## Macro contract (preferred in detections)

Detections should prefer **sourcetype macros** (Splunk macro invoked with backticks) rather than explicit `sourcetype=...` lists:

- `windows_security`
- `windows_system`
- `windows_powershell_operational`
- `windows_powershell_classic`
- `windows_sysmon`

Each macro **must expand** to an OR across:

- Classic channel sourcetypes (`WinEventLog:*`)
- XML channel sourcetypes (`XmlWinEventLog:*`)
- Collapsed sourcetypes (`WinEventLog` / `XmlWinEventLog`) with `source=...` patterns
- Sysmon legacy patterns (`sysmon` / `sysmon:*`) where relevant

See `config/sourcetype_map.yaml` → `macros.*.suggested_definition` for recommended expansions.

### Example usage

Preferred:

```spl
`windows_security` EventCode=4625
| stats count by host, TargetUserName
```

Acceptable:

```spl
sourcetype=WinEventLog:Security EventCode=4625
| stats count by host, TargetUserName
```

## Index scoping rule

- Detections **must not** contain `index=` (case-insensitive). Index scoping is **deploy-time config** only (see `config/org.example.yaml`).

CI enforces this.

## Required fields by Event ID (Phase‑1)

Field names can differ by TA/add-on and normalization; detections should use `coalesce(...)` when necessary and list the **logical required fields** in `required_fields`.

### Windows Security log

| EventCode | Purpose | Minimum required_fields (logical) |
| --- | --- | --- |
| 4624 | Successful logon | `EventCode`, `LogonType`, `TargetUserName`, `IpAddress` (or `src_ip`), `host` |
| 4625 | Failed logon | `EventCode`, `LogonType`, `TargetUserName`, `IpAddress`, `Status`/`SubStatus`, `host` |
| 4648 | Explicit credentials | `EventCode`, `SubjectUserName`, `TargetServerName` (or `dest`), `ProcessName` (or `NewProcessName`), `host` |
| 4672 | Special privileges logon | `EventCode`, `SubjectUserName`, `PrivilegeList`, `host` |
| 4688 | Process creation | `EventCode`, `NewProcessName` (or `Image`), `CommandLine`, `ParentProcessName`, `SubjectUserName`, `host` |
| 4698 | Scheduled task created | `EventCode`, `TaskName`, `TaskContent` (or `Message`), `SubjectUserName`, `host` |
| 4720 | User created | `EventCode`, `TargetUserName`, `SubjectUserName`, `host` |
| 4728 | Member added to global group | `EventCode`, `GroupName`, `MemberName` (or `TargetUserName`), `SubjectUserName`, `host` |
| 4732 | Member added to local group | `EventCode`, `GroupName`, `MemberName`, `SubjectUserName`, `host` |
| 4756 | Member added to universal group | `EventCode`, `GroupName`, `MemberName`, `SubjectUserName`, `host` |
| 4768 | Kerberos AS-REQ | `EventCode`, `TargetUserName`, `IpAddress`, `PreAuthType`, `host` |
| 4769 | Kerberos TGS-REQ | `EventCode`, `Account_Name` (or `TargetUserName`), `ServiceName`, `TicketEncryptionType`, `host` |
| 4771 | Kerberos pre-auth failure | `EventCode`, `TargetUserName`, `IpAddress`, `FailureCode`, `host` |
| 4776 | NTLM validation | `EventCode`, `AccountName`, `Workstation`, `Status`, `host` |
| 1102 | Security log cleared | `EventCode`, `SubjectUserName`, `host` |

### Windows System log

| EventCode | Purpose | Minimum required_fields (logical) |
| --- | --- | --- |
| 7045 | Service installed | `EventCode`, `ServiceName`, `ImagePath` (or `ServiceFileName`), `host` |

### Sysmon (Operational)

| Sysmon EventCode | Purpose | Minimum required_fields (logical) |
| --- | --- | --- |
| 1 | ProcessCreate | `EventCode`, `Image`, `CommandLine`, `ParentImage`, `User`, `host` |
| 3 | NetworkConnect | `EventCode`, `Image`, `DestinationIp`, `DestinationPort`, `User`, `host` |
| 7 | ImageLoad | `EventCode`, `Image`, `ImageLoaded`, `User`, `host` |
| 10 | ProcessAccess | `EventCode`, `SourceImage`, `TargetImage`, `GrantedAccess`, `User`, `host` |
| 11 | FileCreate | `EventCode`, `Image`, `TargetFilename`, `User`, `host` |
| 13 | RegistryValueSet | `EventCode`, `Image`, `TargetObject`, `Details`, `User`, `host` |
| 22 | DNSQuery | `EventCode`, `Image`, `QueryName`, `User`, `host` |

## CI enforcement summary

Validation (`pipelines/validate/validate_repo.py`) enforces:

- `sourcetypes[]` are on the allowlist (`config/sourcetype_map.yaml`)
- Splunk queries contain **`sourcetype=` or a required macro** (e.g., `` `windows_security` ``)
- `index=` is forbidden in any query string (case-insensitive)

