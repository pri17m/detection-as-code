# REVIEW - DAC-MDE-0095 Machine Root/AuthRoot certificate registry key written by an unexpected process

## Attribution
Written clean-room from public sources (Sigma, Splunk security_content, Elastic detection-rules, Microsoft Learn). Inspired by a public LinkedIn post by Maurice Fielenbach describing certmgr.exe copied to a vendor-looking ProgramData path, run as SYSTEM by a sideloaded vendor agent, adding a root CA to the localMachine Root store. No public URL for the post is recorded, so it is credited here and not in references. No screenshot or employer data was used.

## ATT&CK v19.2
- T1553.004 Install Root Certificate - Defense Impairment (TA0112), checked on attack.mitre.org 2026-10-13.

## Existing overlap in this repo
- DAC-WIN-0253 (sigma-wave1, Sysmon 1, "New Root Certificate Installed Via Certutil.EXE"): its query has **no -addstore / root filter** and tables every Sysmon EID 1 event; it needs fixing or retiring.
- DAC-WIN-0212 (ADCS denied enrollment, System 53): tagged T1553.004 but unrelated behaviour (T1649); mis-mapped.
- No CrowdStrike, Defender or registry-based rule for T1553.004 exists on main or in open PRs #44-#53.

## Library research (telemetry each public library uses)
| Library | Rule | Telemetry |
|---|---|---|
| SigmaHQ | proc_creation_win_certutil_certificate_installation / proc_creation_win_certmgr_certificate_installation | process creation (Sysmon 1 / 4688) |
| SigmaHQ | registry_set_install_root_or_ca_certificat | registry set (Sysmon 13) on SystemCertificates / EnterpriseCertificates Root, AuthRoot, CA `\Blob` |
| SigmaHQ | posh_ps_root_certificate_installed | PowerShell script block 4104 |
| Splunk security_content | windows_certutil_root_certificate_addition | process creation via Endpoint.Processes data model; only when cert path is user-writable |
| Elastic detection-rules | defense_evasion_create_mod_root_certificate | registry change on HKLM Root/AuthRoot `\Blob`, with process-path allowlist |
| Azure-Sentinel | none found for this technique | - |
| CrowdStrike logscale-community-content | none found for this technique | - |
| LOLBAS | Certutil entry documents download/encode/decode only, no -addstore; no CertMgr entry | - |
| ATT&CK T1553.004 | tactic Defense Impairment (TA0112) in v19.2 | - |

Recommendation: registry (Root/AuthRoot Certificates key) is the primary, tool-agnostic signal; process creation is the higher-fidelity, easier-to-triage companion and the only one available everywhere by default. CAPI2 Operational (event 90) is off by default and verbose, so it is not used.

## Ponytail review (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Process-only rules miss Import-Certificate, reg import and custom CryptoAPI loaders | `powershell Import-Certificate ... Cert:\LocalMachine\Root` | Watch the Root/AuthRoot Certificates key itself |
| 2 | Must | Matching any value under the key is noisy (FriendlyName, property values) | `...\<thumb>\FriendlyName` | Key create, or value name Blob only |
| 3 | Should | Elastic excludes all of Program Files, letting a sideloaded agent in Program Files through | signed vendor agent under Program Files | Do not exclude Program Files; alert at medium, high for user-writable paths |
| 4 | Should | Excluding all of System32 lets certutil/powershell/reg through | `reg import root.reg` | System32 excluded only for non-LOLBins (Elastic pattern) |
| 5 | Should | HKCU Root is user scope, not machine | HKU\...\Root | Anchor on HKLM / \REGISTRY\MACHINE |
| 6 | Minor | Thumbprint not extracted for baseline comparison | - | Extract thumbprint for baseline/allowlist joins |

Known gaps: Sysmon/MDE registry coverage of this key is config/sampling dependent. Baseline comparison of new thumbprints against a known-good list (Fielenbach's hunting idea) is left to a lookup the org must maintain.

## Field verification
| Field | Status |
|---|---|
| DeviceRegistryEvents fields and HKEY_LOCAL_MACHINE prefix | verified against Microsoft Learn table schema |
| MDE actually records writes under SystemCertificates\Root | **unverified**: MDE registry telemetry is sampled/filtered and coverage of this key is not documented; tag needs-review |
| InitiatingProcessFolderPath contains the full image path | verified in MS docs examples; regex anchors on drive letter |

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0095/; result: not run (repo has no test runner).
