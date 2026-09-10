# Phase-1 required_fields expansion

Merge into `windows-splunk.md` §2.3 (already applied in canonical `windows-splunk.md`).

---

## 2.3 Phase-1 expansion (gap Event IDs) — 2026-09-10

Added to unblock 19 Detection Engineer rules. Same conventions as §2.1–2.2 (native + common aliases; `fieldsummary` before ship).

### Security / PowerShell Operational

| EventCode | Macro / channel | Intent | Required / high-value fields (native) | Common variants / aliases |
| --- | --- | --- | --- | --- |
| **4104** | `windows_powershell_operational` | Script block logging | `EventCode`, `ScriptBlockText`, `ScriptBlockId`, `Path` (may be empty for interactive), `MessageNumber`, `MessageTotal`, `SubjectUserName` / `UserId` when present | `user`, `script`, `cmdline` (rare); often filter on `ScriptBlockText` length/keywords |
| **4662** | `windows_security` | DS object access (e.g. DCSync props) | `SubjectUserName`, `SubjectDomainName`, `ObjectServer`, `ObjectType`, `ObjectName` / `ObjectDN`, `ObjectGUID`, `Properties`, `AccessMask`, `AdditionalInfo` | `user`, `object`, `object_path`; DCSync hunts need replication GUIDs in `Properties` |
| **4702** | `windows_security` | Scheduled task updated | `TaskName`, `SubjectUserName`, `SubjectDomainName`, `TaskContent` / updated XML when logged | `user`, `object`, `command` (from task XML — often needs `rex*) |
| **4719** | `windows_security` | System audit policy changed | `SubjectUserName`, `SubjectDomainName`, `CategoryId`, `SubcategoryId`, `SubcategoryGuid`, `AuditPolicyChanges` | `user`, `object`; sparse on some collectors — host+EventCode may be baseline |
| **4724** | `windows_security` | Password reset attempt | `SubjectUserName`, `SubjectDomainName`, `TargetUserName`, `TargetDomainName`, `TargetSid` | `src_user`, `user` |
| **4738** | `windows_security` | User account changed | `SubjectUserName`, `SubjectDomainName`, `TargetUserName`, `TargetDomainName`, `SamAccountName`, `PasswordLastSet`, `UserAccountControl`, `OldUacValue`, `NewUacValue`, `UserParameters`, `SidHistory`, `AllowedToDelegateTo` (as present) | `user`, `src_user`, `object`; many fields `-` when unchanged — detect on non-dash deltas |
| **4740** | `windows_security` | Account locked out | `TargetUserName`, `TargetDomainName`, `SubjectUserName` (caller often machine$), `Caller_Computer_Name` / `CallerComputerName` | `user`, `src`, `dest` |
| **4741** | `windows_security` | Computer account created | `TargetUserName`, `TargetDomainName`, `SubjectUserName`, `SubjectDomainName`, `SamAccountName`, `ServicePrincipalNames` when present | `user` (computer$), `src_user`, `dest` |
| **4886** | `windows_security` | Certificate Services — certificate request received | `RequestId`, `Requester` / `SubjectUserName`, `Attributes`, `Subject` (when parsed) | `user`, `object`; AD CS channel — confirm org enables CA audit |
| **4887** | `windows_security` | Certificate Services — request approved | `RequestId`, `Requester`, `Attributes`, `Subject` | `user`, `object` |
| **4888** | `windows_security` | Certificate Services — request denied | `RequestId`, `Requester`, `Attributes`, `StatusCode` / reason fields when present | `user`, `object`, `result` |
| **5136** | `windows_security` | Directory Service object modified | `SubjectUserName`, `SubjectDomainName`, `ObjectDN`, `ObjectGUID`, `ObjectClass`, `AttributeLDAPDisplayName`, `AttributeValue`, `OperationType`, `DSName`, `AppCorrelationID` | `user`, `object`, `object_attrs`; pair create/delete with 5137/5139 |
| **5137** | `windows_security` | Directory Service object created | `SubjectUserName`, `SubjectDomainName`, `ObjectDN`, `ObjectGUID`, `ObjectClass`, `DSName` | `user`, `object` |
| **5145** | `windows_security` | Network share object checked (detailed) | `SubjectUserName`, `SubjectDomainName`, `ShareName`, `ShareLocalPath`, `RelativeTargetName`, `AccessMask`, `AccessList`, `IpAddress`, `IpPort`, `ObjectType` | `user`, `src`, `file_path`, `file_name`; noisy — prefer sensitive share/`RelativeTargetName` patterns |

### Sysmon (prefer `windows_sysmon` / XML)

| EventCode | Intent | Required / high-value fields | CIM / TA aliases (when present) |
| --- | --- | --- | --- |
| **4** | Sysmon service state changed | `State`, `Version`, `SchemaVersion` (sparse) | `status`, `service`; often host-scoped integrity signal |
| **6** | Driver loaded | `ImageLoaded`, `Hashes`, `Signed`, `Signature`, `SignatureStatus` | `file_path`, `file_name`, `process_hash` |
| **8** | CreateRemoteThread | `SourceImage`, `TargetImage`, `NewThreadId`, `StartAddress`, `StartModule`, `StartFunction`, `SourceProcessGuid`, `TargetProcessGuid`, `SourceUser`, `TargetUser` | `process`, `dest_process`, `user` |
| **16** | Sysmon config changed | `Configuration`, `ConfigurationFileHash` | `object`, `file_hash` |
| **17** | Named pipe created | `PipeName`, `Image`, `ProcessGuid`, `User` | `process`, `object`, `user` |
| **18** | Named pipe connected | `PipeName`, `Image`, `ProcessGuid`, `User` | `process`, `object`, `user` |
| **19** | WMI event filter | `EventNamespace`, `Name`, `Query`, `User`, `Operation` | `user`, `object`, `query` |
| **20** | WMI event consumer | `Name`, `Type`, `Destination`, `User`, `Operation` | `user`, `object`, `dest` |
| **21** | WMI consumer→filter binding | `Consumer`, `Filter`, `User`, `Operation` | `user`, `object` |
| **25** | Process tampering (image change) | `Image`, `Type`, `User`, `ProcessGuid` | `process`, `user`, `action` |

### Sourcetype notes for this expansion

- **4104** → `windows_powershell_operational` only (not classic PowerShell channel).
- **4662 / 5136 / 5137 / 5145 / 47xx / 4719 / 4886–4888** → `windows_security`.
- **Sysmon 4/6/8/16/17–21/25** → `windows_sysmon` (XML preferred; need Sysmon config that actually emits these IDs — many orgs disable 17–21/25).
- **AD CS (4886–4888):** data gap if CA audit logging not forwarded; do not assume presence.
- **4662:** extremely noisy; detections should constrain `Properties` / access masks (e.g. replication) after org validation.
