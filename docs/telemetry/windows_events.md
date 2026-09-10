# Windows telemetry (Splunk) — Event IDs, fields, sourcetypes

## Canonical sourcetypes

Detections in this repo rely on canonical sourcetypes (see `config/sourcetype_map.yaml`):

- **Security**: `WinEventLog:Security` (or `XmlWinEventLog:Security`)
- **System**: `WinEventLog:System` (or `XmlWinEventLog:System`)
- **Sysmon**: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **PowerShell**: `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`
- **WMI Activity**: `XmlWinEventLog:Microsoft-Windows-WMI-Activity/Operational`
- **Windows Defender**: `XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational`

If your deployment uses different sourcetypes, map them in your org config to these canonical values.

## Phase‑1 Windows Security Event IDs (Security log)

These are the primary Event IDs covered in the Phase‑1 Splunk rules:

- **4624** Successful logon
- **4625** Failed logon
- **4634** Logoff
- **4648** Logon with explicit credentials
- **4672** Special privileges assigned to new logon
- **4688** Process creation (requires Audit Process Creation enabled; command line requires policy)
- **4698 / 4702** Scheduled task created / updated
- **4719** System audit policy changed
- **4720 / 4722 / 4726** User created / enabled / deleted
- **4728 / 4732 / 4756** Member added to group (domain local / local / universal)
- **4738** User account changed
- **4740** Account locked out
- **4768 / 4769** Kerberos authentication service / ticket events
- **4771 / 4776** Kerberos pre-auth failed / NTLM authentication
- **1102** Audit log cleared

## Recommended field normalization

Detections prefer **CIM-like fields** when present:

- **Identity**: `user`, `src_user`, `dest_user`, `Account_Name`, `TargetUserName`
- **Network**: `src`, `src_ip`, `dest`, `dest_ip`, `IpAddress`
- **Process**: `process_name`, `process`, `parent_process_name`, `CommandLine`, `NewProcessName`, `ParentProcessName`
- **Host**: `host`, `ComputerName`

In Splunk, using the Splunk CIM and the Windows TA/add-ons to normalize fields will materially improve rule portability and reduce per-org rewriting.

## Sysmon (optional, strongly recommended)

If Sysmon is onboarded, enable the canonical sourcetype and ensure key events are ingested:

- **1** Process creation
- **3** Network connection
- **7** Image loaded
- **8** CreateRemoteThread
- **10** Process access
- **11** File create
- **13** Registry value set
- **22** DNS query

Rules in this repo that require Sysmon are gated by `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` and can be enabled once telemetry is available.

