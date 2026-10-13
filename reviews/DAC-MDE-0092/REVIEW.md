# REVIEW — DAC-MDE-0092 Unexpected SyncRootManager cloud sync root registration

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a095bb-647d-771a-9ed0-c98dc5b7a276 by Arnold Chan (@slaz). No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## CVE verification
- CVE-2026-69414: **found**, but **mismatched** to the source rule's claimed behaviour.
  - NVD: elevation of privilege in Microsoft Malware Protection Engine, publicly referred to as "ShieldBreak".
  - MSRC: Microsoft Defender Elevation of Privilege.
  - NVD reference also lists https://github.com/MSNightmare/ShieldBreak (HTTP 404 when fetched 2026-10-13).
  - No NVD/MSRC text about Cloud Filter, CfRegisterSyncRoot, or "ShieldCrash".
- Decision per brief: write as **generic** SyncRootManager registration behaviour; **CVE omitted from references**; tag `needs-review`.

## ATT&CK v19.2
- T1112 Modify Registry — defense-impairment, persistence (mapped persistence via stealth/persistence tactics used: stealth is T1553.002's tactic; T1112 contributes persistence)
- T1553.002 Code Signing — defense-impairment (unsigned binary registering sync root)

Tactics on the rule: stealth, persistence (T1112 kill chain includes persistence; T1553.002 is defense-impairment — prefer defense-impairment + persistence).

Correction: use defense-impairment + persistence to match STIX.

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Source matched ActionType/AdditionalFields strings "CloudProviderRegistered", "ShieldCrash_" — none of those ActionType values appear in Microsoft Learn DeviceEvents docs; tying to CVE-2026-69414 is wrong | Any event with AdditionalFields containing ShieldCrash_ | Replaced with DeviceRegistryEvents on documented SyncRootManager key path; dropped CVE from references |
| 2 | Should | Source `InitiatingProcessSHA1 !in ("")` is a no-op filter | empty SHA1 | Removed; leftouter join on certificate info instead |
| 3 | Should | Hard dependency on unverified CloudProvider* ActionTypes | Tenant without those ActionTypes → silent miss | Use RegistryKeyCreated / RegistryValueSet (Learn DeviceRegistryEvents) |

## Field verification
| Field | Status | Source |
|---|---|---|
| SyncRootManager registry path | verified | https://learn.microsoft.com/en-us/windows/win32/shell/integrate-cloud-storage |
| DeviceRegistryEvents ActionType RegistryKeyCreated / RegistryValueSet | verified | Microsoft Learn DeviceRegistryEvents |
| DeviceFileCertificateInfo IsSigned, Signer, SHA1 | verified | Microsoft Learn DeviceFileCertificateInfo |
| CloudProviderRegistered / CloudProviderAttached / CloudProviderCallback | unverified (not used) | not in Learn DeviceEvents ActionType list reviewed 2026-10-13 |

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0092/; result: not run.
