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

## Field / telemetry verification
| Item | Status | Source |
|---|---|---|
| WMI-Activity Event ID 11 fields Operation, ClientProcessId | verified | https://isc.sans.edu/diary/25012 sample XML |
| Trace channel enablement | verified (required) | https://learn.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity |
| Image / ProcessId on the WMI event itself | unverified (not used) | SANS sample has ClientProcessId, not Image |
| Sysmon 19-21 | not used | those IDs are WMI permanent-event registration, not ExecQuery text |

## Tests
Synthetic fixtures under tests/cases/DAC-WIN-0361/; result: not run.
