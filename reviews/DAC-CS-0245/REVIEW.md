# REVIEW - DAC-CS-0245 Falcon: PHP runtime spawns a shell that stacks recon/download/revshell/tmp-exec (PHP2Shell post-exploitation)

## Attribution
Clean-room behavioural rule for PHP2Shell post-exploitation. Primary sources opened:
- Datadog Security Labs PHP2Shell article (CVE-2026-109618, CVE-2026-109619)
- AWS MadPot blog (exploitation from 17 Oct 2026, before 21 Oct disclosure)
- GitHub advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp on php/php-src
No exploit code, no employer telemetry, no payload logs. Fixtures are SYNTHETIC and marked not run.

## As-is (new)
No prior PHP2Shell or PHP-runtime-shell-stacking rule in this library. SigmaHQ Linux webshell rules exist publicly but do not require multi-class stacking and often omit php-fpm as parent.

## After
New crowdstrike rule DAC-CS-0245: PHP runtime parent -> shell child, alert when >=2 of {recon, download, revshell, tmpexec} appear for one host within 10 minutes.
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
- ProcessRollup2 field names verified only against public secondary sources and sibling repo rules — confirm in Events Data Dictionary; bucket()/case LogScale dialect not run
- telemetry_validated false; no real PHP2Shell payload logs in public sources at write time
- Exact php-fpm worker FileName / InitiatingProcessFileName forms per EDR build
- Whether Falcon shows apache2 (not php module) as ParentBaseFileName for mod_php

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0245/; result: **not run** (no SIEM runner; no lab payload). Each fixture sets `"synthetic": true` and `"result": "not run"`.

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
