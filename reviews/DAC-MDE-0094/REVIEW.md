# REVIEW - DAC-MDE-0094 Root CA added to the machine Root store with certutil -addstore or certmgr -add localMachine

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
| 1 | Must | Image-name matching (Sigma, Splunk) misses renamed or copied binaries, which is exactly the Fielenbach tradecraft | `svc.exe -addstore -f root ca.cer` | Match on arguments; report/flag OriginalFileName where the platform has it |
| 2 | Must | `CommandLine contains root` matches any path containing "root" | `certutil -addstore My C:\root\client.pfx` | Root/AuthRoot must be a whitespace-delimited argument |
| 3 | Must | Sigma certutil rule also fires on `-user` (per-user store), which is not machine scope | `certutil -addstore -user root x.cer` | Exclude `-user`; certmgr requires `-r localMachine` |
| 4 | Should | Splunk content only alerts when the .cer sits in a user-writable path, so an attacker cert in C:\Windows\Tasks or a UNC path is missed | `certutil -addstore root \\host\s\a.cer` | Alert on every machine-scope add; escalate rather than filter |
| 5 | Should | No escalation for unexpected image location or parent | certmgr in ProgramData spawned by vendor agent | Severity high when path/name or parent is unexpected |
| 6 | Minor | Sigma certmgr OriginalFileName is CERTMGT.EXE, post shows CertMgr.Exe | - | Accept both where OriginalFileName is used |

Known gaps (documented, not fixed): PowerShell `Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root` and direct CryptoAPI calls do not use these binaries - covered by the companion registry rule. Command-line obfuscation (caret insertion, quoted flag fragments) is not normalised.

## Field verification
| Field | Status |
|---|---|
| DeviceProcessEvents fields incl. ProcessVersionInfoOriginalFileName | verified against Microsoft Learn table schema |
| certmgr OriginalFileName value | **unverified**: Sigma uses CERTMGT.EXE, the inspiration post shows CertMgr.Exe; both accepted (lower-cased) |

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0094/; result: not run (repo has no test runner).
