# REVIEW - DAC-WIN-0364 Root CA added to the machine Root store via PowerShell (script block 4104)

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


## Variant matrix (hardening pass, ponytail)
| Variant | Source | Caught before | Caught after | Fixture |
|---|---|---|---|---|
| Import-Certificate ... Cert:\LocalMachine\Root | SigmaHQ posh_ps_root_certificate_installed | n/a (new rule) | yes | malicious_import_certificate |
| Import-PfxCertificate ... Cert:\LocalMachine\Root | SigmaHQ posh_ps_root_certificate_installed | n/a (new rule) | yes | malicious_import_pfx |
| Move-Item to Cert:\LocalMachine\Root | Atomic Red Team T1553.004 | n/a (new rule) | yes | malicious_move_item_atomic |
| X509Store Root/LocalMachine Add() | .NET X509Store docs | n/a (new rule) | yes | malicious_x509store_add |
| script decoded from -enc (4104 logs decoded text) | Microsoft about_Logging docs | n/a (new rule) | yes | malicious_decoded_enc |
| P/Invoke CertAddEncodedCertificateToStore to LocalMachine Root | Microsoft crypt32 docs | n/a (new rule) | yes | malicious_pinvoke_crypt32 |
| store path built by string concatenation | Common command-line obfuscation (dash/quote/caret); Sigma |windash modifier | n/a (new rule) | **no** | knowngap_string_concat |
| Get-ChildItem Cert:\LocalMachine\Root | PowerShell certificate provider docs | n/a (new rule) | no alert (correct) | near_miss_read_root |
| Import-Certificate to Cert:\CurrentUser\Root (user scope) | Atomic Red Team T1553.004 | n/a (new rule) | no alert (correct) | near_miss_currentuser_root |
| Remove-Item from Cert:\LocalMachine\Root | Atomic Red Team T1553.004 cleanup | n/a (new rule) | no alert (correct) | near_miss_remove_root |

### Scope decisions
- In scope: machine-scope **Root** and **AuthRoot** (trust anchors), including the Enterprise (`-enterprise`) and Group Policy (`-grouppolicy`, `Policies\...`) machine stores.
- Out of scope, documented: **CA** (intermediate store, does not create trust on its own), **TrustedPublisher** (code-signing publisher trust, closer to T1553.002/.006), **Disallowed** (removes trust; delstore-style tampering), and all **user-scope** stores (`-user`, `Cert:\CurrentUser`, HKCU/HKU). Atomic test 7 (CurrentUser via RemoteCertTrust.ps1) is therefore intentionally not covered.
- Caret insertion and `%VAR%` / `%VAR:~x,y%` substring obfuscation are resolved by cmd.exe **before** the child process starts, so certutil's own command line is normally clean; the rules also strip `^`, quotes and Unicode dashes (U+2010-U+2015, U+2212) in case the child line carries them (e.g. launched via PowerShell or CreateProcess). Unexpanded `%VAR%` in a child launched without cmd is a known gap.
- msiexec stays an "expected" parent (medium) because legitimate MSI custom actions install corporate roots; scheduled tasks (svchost parent), services (services.exe) and sideloaded vendor agents are unexpected (high).

### Remaining gaps (stand-in matcher misses)
knowngap_string_concat
Known-gap fixtures (expected misses, covered elsewhere): knowngap_string_concat -> script block rule DAC-WIN-0364 (Splunk) / registry rules

Stand-in matcher: `/workspace/rootca-gen/gen2.py` (Python re reimplementation of the query logic, run on the box 2026-10-13). It is not the SIEM engine; CQL/KQL/SPL escaping and Unicode handling remain unverified until run in a tenant.

## Field verification
| Field | Status |
|---|---|
| 4104 ScriptBlockText, ScriptBlockId, Path | verified (Sigma posh_ps rules; Splunk Add-on for Windows XML rendering) |
| Defender PowerShellCommand / CrowdStrike ScriptControl equivalents | **not written**: Defender PowerShellCommand logs cmdlet names without arguments, and CrowdStrike ScriptControl field names were not verifiable from public sources |
| SPL regex escaping | **unverified**: not run in Splunk |

## Tests
Synthetic fixtures under tests/cases/DAC-WIN-0364/; result: not run (repo has no test runner).
