# REVIEW — DAC-CS-0240 Falcon: BYOVD-style kernel driver / sc kernel service from user-writable path

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a13344-27be-72b1-ba24-630ada1d8f86 by Fatima Suvaid (@arhaminafs). No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## Coverage before / after
New. Covers T1068 / T1685 / T1543.003 BYOVD staging on Falcon.

## ATT&CK v19.2
- T1068 Exploitation for Privilege Escalation — privilege-escalation
- T1685 Disable or Modify Tools — defense-impairment (replaces revoked T1562.001)
- T1543.003 Windows Service — persistence, privilege-escalation

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Source branch "KnownBYOVDDriverLoad" fires on any path for a known basename, so `C:\Windows\System32\drivers\truesight.sys` from a vendor install alerts | DriverLoad ImageFileName=`C:\Windows\System32\drivers\truesight.sys` | Dropped path-free DriverLoad name branch; known-name sc.exe branch now also requires a user-writable path |
| 2 | Must | Source used `#event_simpleName=ServiceInstalled` — 0 hits in CrowdStrike logscale-community-content; field set unverified | Any ServiceInstalled event | Removed ServiceInstalled from the query |
| 3 | Should | Source "KnownBYOVDServiceCmd" without path: `sc start truesight` from System32 alerts on a leftover service name | `sc.exe start truesight` | Require Temp/ProgramData/Users\Public/Downloads in CommandLine |
| 4 | Should | No unsigned-driver gate | Signed vendor driver staged in Temp | Documented; SignInfoFlags on DriverLoad unverified in public docs — left as open question, tag needs-review |
| 5 | Nice | Source table() only — no aggregation for Filter Alerts | — | groupBy for scheduled-search shape |

## Field verification
| Field / ESN | Status | Source |
|---|---|---|
| DriverLoad | verified | https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Enumerate%20Windows%20Driver%20Loads.md |
| ProcessRollup2, ImageFileName, CommandLine, aid, ComputerName | verified | same repo Helpful-CQL / Combine ProcessRollup2 docs |
| ServiceInstalled | unverified (removed) | 0 matches in logscale-community-content snapshot 2026-10-13 |
| SignInfoFlags on DriverLoad | unverified | Decode SignInfoFlags.md shows ProcessRollup2 only |

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0240/; result: not run (no runner).
