# REVIEW - DAC-WIN-0362 Root CA added to the machine Root store with certutil -addstore or certmgr -add localMachine (Sysmon 1)

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


## Variant matrix (hardening pass, ponytail)
| Variant | Source | Caught before | Caught after | Fixture |
|---|---|---|---|---|
| certutil -f -addstore root | Atomic Red Team T1553.004 | yes | yes | malicious_certutil_f_addstore_root |
| certutil -addstore -enterprise root | Microsoft certutil docs | yes | yes | malicious_certutil_enterprise_root |
| certutil -grouppolicy -addstore root | Microsoft certutil docs | yes | yes | malicious_certutil_grouppolicy_root |
| certutil -v -addstore authroot | Microsoft certutil docs | yes | yes | malicious_certutil_v_authroot |
| certutil /addstore root | SigmaHQ certutil/certmgr rules | yes | yes | malicious_certutil_slash_form |
| en dash –addstore | Common command-line obfuscation (dash/quote/caret); Sigma |windash modifier | **no** | yes | malicious_certutil_en_dash |
| em dash —addstore | Common command-line obfuscation (dash/quote/caret); Sigma |windash modifier | **no** | yes | malicious_certutil_em_dash |
| U+2010 hyphen | Common command-line obfuscation (dash/quote/caret); Sigma |windash modifier | **no** | yes | malicious_certutil_u2010_hyphen |
| quoted "Root" | Common command-line obfuscation (dash/quote/caret); Sigma |windash modifier | yes | yes | malicious_certutil_quoted_store |
| quote inside flag -"addstore" | Common command-line obfuscation (dash/quote/caret); Sigma |windash modifier | **no** | yes | malicious_certutil_quote_in_flag |
| caret left in child command line | Common command-line obfuscation (dash/quote/caret); Sigma |windash modifier | **no** | yes | malicious_certutil_caret_in_child |
| certutil -importpfx root | Microsoft certutil docs | **no** | yes | malicious_certutil_importpfx_root |
| certmgr /add /all ... /s /r localMachine root | Microsoft certmgr docs; Sigma example | yes | yes | malicious_certmgr_all_flag |
| certmgr -add -c x -r localMachine -s root | Microsoft certmgr docs | yes | yes | malicious_certmgr_arg_order |
| certmgr copied to ProgramData, sideloaded vendor parent, SYSTEM | Fielenbach public post | yes | yes | malicious_certmgr_programdata_vendor_parent |
| renamed certutil (OriginalFileName CertUtil.exe) | Splunk/Sigma OriginalFileName pattern | yes | yes | malicious_renamed_certutil |
| Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root | SigmaHQ posh_ps_root_certificate_installed | **no** | yes | malicious_ps_import_certificate |
| Move-Item to Cert:\LocalMachine\Root | Atomic Red Team T1553.004 | **no** | yes | malicious_ps_move_item |
| cpi alias to Cert:\LocalMachine\AuthRoot | PowerShell certificate provider docs | **no** | yes | malicious_ps_copy_item_alias |
| X509Store('Root','LocalMachine').Add() | .NET X509Store docs | **no** | yes | malicious_ps_x509store_add |
| X509Store StoreName/StoreLocation enums | .NET X509Store docs | **no** | yes | malicious_ps_x509store_enum |
| reg add HKLM ...\ROOT\Certificates\<t> /v Blob | Sigma/Elastic registry rules (path) | **no** | yes | malicious_reg_add_blob |
| certutil from a scheduled task (svchost parent) | ATT&CK T1053 context | yes | yes | malicious_scheduled_task_parent |
| certutil from a service (services.exe child) | ATT&CK T1543.003 context | yes | yes | malicious_service_parent |
| certutil from msiexec custom action | MSI custom action pattern | yes | yes | malicious_msiexec_custom_action |
| reg import root.reg (content not on command line) | Sigma/Elastic registry rules | **no** | **no** | knowngap_reg_import |
| powershell -enc (script hidden) | Common PowerShell obfuscation | **no** | **no** | knowngap_ps_encoded |
| rundll32 cryptext.dll,CryptExtAddCER (UI wizard) | LOLBAS-style shell handler for .cer | **no** | **no** | knowngap_rundll32_cryptext |
| %VAR% left unexpanded in child (e.g. launched without cmd) | Common command-line obfuscation (dash/quote/caret); Sigma |windash modifier | **no** | **no** | knowngap_env_var_in_child |
| certutil -verifystore root | Microsoft certutil docs | no alert (correct) | no alert (correct) | near_miss_verifystore_root |
| certutil -viewstore root | Microsoft certutil docs | no alert (correct) | no alert (correct) | near_miss_viewstore_root |
| certutil -user -addstore root (user scope, out of scope) | Microsoft certutil docs | no alert (correct) | no alert (correct) | near_miss_user_root |
| certutil –user –addstore root | Microsoft certutil docs | no alert (correct) | no alert (correct) | near_miss_user_root_unicode_dash |
| certutil -addstore CA (intermediate, out of scope) | Microsoft certutil docs | no alert (correct) | no alert (correct) | near_miss_ca_store |
| certutil -addstore TrustedPublisher (code-signing trust, out of scope) | Microsoft certutil docs | no alert (correct) | no alert (correct) | near_miss_trustedpublisher |
| certutil -addstore Disallowed (removes trust) | Microsoft certutil docs | no alert (correct) | no alert (correct) | near_miss_disallowed |
| certutil -delstore root | Microsoft certutil docs | no alert (correct) | no alert (correct) | near_miss_delstore_root |
| root only in a file path | SigmaHQ certutil/certmgr rules | no alert (correct) | no alert (correct) | near_miss_root_in_path_only |
| certmgr -r currentUser root | Microsoft certmgr docs | no alert (correct) | no alert (correct) | near_miss_certmgr_currentuser |
| Get-ChildItem Cert:\LocalMachine\Root (read) | PowerShell certificate provider docs | no alert (correct) | no alert (correct) | near_miss_ps_read_root |
| Import-Certificate to Cert:\CurrentUser\Root (user scope) | Atomic Red Team T1553.004 | no alert (correct) | no alert (correct) | near_miss_ps_import_currentuser |

### Scope decisions
- In scope: machine-scope **Root** and **AuthRoot** (trust anchors), including the Enterprise (`-enterprise`) and Group Policy (`-grouppolicy`, `Policies\...`) machine stores.
- Out of scope, documented: **CA** (intermediate store, does not create trust on its own), **TrustedPublisher** (code-signing publisher trust, closer to T1553.002/.006), **Disallowed** (removes trust; delstore-style tampering), and all **user-scope** stores (`-user`, `Cert:\CurrentUser`, HKCU/HKU). Atomic test 7 (CurrentUser via RemoteCertTrust.ps1) is therefore intentionally not covered.
- Caret insertion and `%VAR%` / `%VAR:~x,y%` substring obfuscation are resolved by cmd.exe **before** the child process starts, so certutil's own command line is normally clean; the rules also strip `^`, quotes and Unicode dashes (U+2010-U+2015, U+2212) in case the child line carries them (e.g. launched via PowerShell or CreateProcess). Unexpanded `%VAR%` in a child launched without cmd is a known gap.
- msiexec stays an "expected" parent (medium) because legitimate MSI custom actions install corporate roots; scheduled tasks (svchost parent), services (services.exe) and sideloaded vendor agents are unexpected (high).

### Remaining gaps (stand-in matcher misses)
knowngap_reg_import, knowngap_ps_encoded, knowngap_rundll32_cryptext, knowngap_env_var_in_child
Known-gap fixtures (expected misses, covered elsewhere): knowngap_reg_import -> registry rule DAC-MDE-0095/DAC-WIN-0363; knowngap_ps_encoded -> script block rule DAC-WIN-0364 (Splunk) / registry rules; knowngap_rundll32_cryptext -> registry rule DAC-MDE-0095/DAC-WIN-0363; knowngap_env_var_in_child -> registry rule DAC-MDE-0095/DAC-WIN-0363

Stand-in matcher: `/workspace/rootca-gen/gen2.py` (Python re reimplementation of the query logic, run on the box 2026-10-13). It is not the SIEM engine; CQL/KQL/SPL escaping and Unicode handling remain unverified until run in a tenant.

## Field verification
| Field | Status |
|---|---|
| Sysmon EID 1 Image, OriginalFileName, CommandLine, ParentImage, Hashes | verified (Sysmon schema; field names as rendered by Splunk Add-on for Sysmon) |
| SPL regex escaping (\x22, doubled backslashes) | **unverified**: not run in Splunk |

## Tests
Synthetic fixtures under tests/cases/DAC-WIN-0362/; result: not run (repo has no test runner).
