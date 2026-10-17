# REVIEW — DAC-WIN-0361 WMI five-query host fingerprint burst

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a130b2-62e5-7332-9d5c-0d19c3cb0750 by Adarsh Pandey (@Pandeyadarsh). No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## ATT&CK v19.2
- T1082 System Information Discovery — discovery
- T1047 Windows Management Instrumentation — execution

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Source used `index=your_index` — forbidden by repo CI | any | Removed all index= |
| 2 | Must | Source used placeholder sourcetype and assumed fields Image / ProcessId / Query | Events with only Operation + ClientProcessId (SANS EID 11 sample) | sourcetype=WinEventLog OR XmlWinEventLog (allowed); match source WMI-Activity; group by ClientProcessId; coalesce Operation/Query/message/_raw |
| 3 | Should | Exact SELECT strings miss case/field-order variants | `select SerialNumber from Win32_BIOS` vs source's `SELECT SerialNumber FROM Win32_BIOS` | Class+property match instead of full SELECT literal; kept cs (ComputerSystem) required |
| 4 | Should | Event ID 11 is on the **Trace** channel, not Operational; often disabled | Estate without Trace enabled → permanent miss | Documented enablement; tag needs-review; telemetry_validated false |

### Merge-time ponytail pass (2026-10-17) — NOT MERGED, telemetry gate open

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| M1 | Should | Title said "Five ... queries" but the logic alerts on 4 of 5 (with Win32_ComputerSystem required) | 4 queries incl. ComputerSystem → alert titled "Five" | Title now "Four or more of five ... (including Win32_ComputerSystem) ... in a 5-minute bucket" |
| M2 | Should | `first_seen` was `min(_time)` after `bin _time span=5m`, so it reported the bucket start, not the first query | First query at 10:03:41 → first_seen 10:00:00 | Keep raw time in `event_time` before `bin`; output `first_seen`/`last_seen` from it |
| M3 | Must (blocker) | Event ID 11 lives on `Microsoft-Windows-WMI-Activity/Trace`, an Analytic/Debug ("direct") channel. Microsoft: "You cannot subscribe to an Analytic or Debug channel; the events ... go directly to a log file" (ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL, 15009). A standard Splunk `WinEventLog://` input therefore cannot collect it; Splunk .conf 2019 SEC1550 also says Splunk cannot read the Trace format directly and uses a PowerShell relay | Default UF with `[WinEventLog://Microsoft-Windows-WMI-Activity/Trace]` → subscription error, no events, rule silently never fires | Not fixable from public sources inside this rule: the WMI-Activity/Operational channel (5857-5861) does not carry successful query text. Left open until a supported collection path (ETW relay / exported evtx) and its sourcetype are chosen and added to config/sourcetype_map.yaml |

Sources for M3: https://learn.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity ; https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log-error-constants (15009: Analytic/Debug channels cannot be subscribed to) ; https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-when-enabling-analytic-debug-event-log (names WMI-Activity/Trace as an analytic/debug log) ; https://community.splunk.com/t5/Getting-Data-In/How-to-collect-Windows-event-logs-that-are-not-from-evtx-or-evt/m-p/240376 ; https://conf.splunk.com/files/2019/slides/SEC1550.pdf

## Field / telemetry verification
| Item | Status | Source |
|---|---|---|
| WMI-Activity Event ID 11 fields Operation, ClientProcessId | verified | https://isc.sans.edu/diary/25012 sample XML |
| Trace channel enablement | verified (required) | https://learn.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity |
| Image / ProcessId on the WMI event itself | unverified (not used) | SANS sample has ClientProcessId, not Image |
| Sysmon 19-21 | not used | those IDs are WMI permanent-event registration, not ExecQuery text |

## Tests
Synthetic fixtures under tests/cases/DAC-WIN-0361/; result: not run.
