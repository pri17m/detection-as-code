# REVIEW — DAC-MDE-0091 Chrome tree spawns SYSTEM LOLBin / user-writable path

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a0ce0d-aa97-716a-af05-95e79cb341ae by Arnold Chan (@slaz). No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## CVE verification
- CVE-2026-85880: **found**. NVD: "Heap-based buffer overflow in Windows ALPC allows an authorized attacker to elevate privileges locally." MSRC title: Windows ALPC Elevation of Privilege. Exploited=Yes on MSRC. https://nvd.nist.gov/vuln/detail/CVE-2026-85880 https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85880
- "BlueMoon" exploit-kit branding: **not** present in NVD/MSRC text. Kept out of the rule title/claims; CVE kept because the ALPC LPE itself is verified.

## ATT&CK v19.2
- T1068 Exploitation for Privilege Escalation — privilege-escalation
- T1203 Exploitation for Client Execution — execution

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Should | Source required Chrome path only on InitiatingProcessFolderPath, so a grandparent-chrome case with a non-Chrome intermediate parent and a fake chrome.exe path could slip the path check while still matching ParentFileName | Intermediate `helper.exe` with Parent chrome, InitiatingProcessFolderPath outside Google\Chrome | Kept path check OR parent-name chrome; documented residual gap when only ParentFileName matches |
| 2 | Should | No lookback bound | Full table scan | `Timestamp > ago(1d)` |
| 3 | Nice | AccountDomain check complements AccountName | SYSTEM under NT AUTHORITY | Kept both (source had both) |

## Field verification
| Field | Status | Source |
|---|---|---|
| DeviceProcessEvents AccountName, FolderPath, InitiatingProcess* | verified | Microsoft Learn DeviceProcessEvents |

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0091/; result: not run.
