# REVIEW - DAC-CS-0250 Falcon: touch copies or sets a timestamp on a systemd, cron, rc.local, shell profile or bin path

## Attribution
Clean-room behavioural rule written from public sources opened on 12 Nov 2026 (IST):
- https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
- https://github.com/hackerschoice/gsocket/blob/master/deploy/deploy.sh
- https://attack.mitre.org/techniques/T1070/006/
- https://github.com/CrowdStrike/logscale-community-content

The Microsoft blog's own hunting queries match tool names, hosts, hashes and fixed file names. This rule does not copy them and does not use any IOC as its trigger. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No rule in this repo matched this behaviour on main at 9a7a7d9 (searched for gsocket, exec -a, GS_ARGS, hidden temp-path execution and touch timestamp options).

## After
New crowdstrike rule DAC-CS-0250 on ProcessRollup2 (event_platform=Lin). Companion: DAC-MDE-0101.

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1070.006; tactics stealth.

## Existing overlap in this repo
None found.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Timestamp set through a script interpreter or debugfs | No touch process | Known gap |
| Target path passed via a variable in a script | Only the script is on the command line | Known gap |
| Other target folders such as ~/.config | Path list | Known gap |

## Unverified
- Volume from package and config management on real hosts.
- Whether busybox touch shows as touch in ImageFileName/FileName.
- Field names come from logscale-community-content Linux queries (ProcessRollup2, event_platform=Lin, UID, ParentBaseFileName, GrandParentBaseFileName, ImageFileName, CommandLine); query not run in LogScale.
- telemetry_validated false.

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0250/. Each has `"synthetic": true` and `result` "not run". There is no LogScale or Advanced Hunting runner here. As a supplement, the rule's regexes were mirrored in Python and applied to the fixture events. That checks the patterns only, not the query language.

| Fixture | Expect alert | Regex check | Result |
|---|---|---|---|
| malicious_0 | yes | would alert | match |
| malicious_1 | yes | would alert | match |
| benign_2 | no | no alert | match |
| near_miss_3 | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Draft only matched -r/--reference and missed -t on the systemd link | `touch -h -t 2023... defunct.service (malicious_1)` | Match -t, -d, --date and combined short flags |
| 2 | Should | Plain touch on a unit file has no timestamp change intent | `touch /etc/systemd/system/app.service (near_miss_3)` | Require a timestamp option |
| 3 | Should | Reference timestamp on a non-persistence path | `touch -r /etc/hosts /tmp/marker (near_miss_3)` | Require a persistence or bin target path |

## Reviewer status
pending
