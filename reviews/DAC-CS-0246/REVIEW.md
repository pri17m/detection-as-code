# REVIEW - DAC-CS-0246 Falcon: Linux process presents a kernel-thread-style name (exec -a or bracketed argv0)

## Attribution
Clean-room behavioural rule written from public sources opened on 12 Nov 2026 (IST):
- https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
- https://github.com/hackerschoice/gsocket/blob/master/deploy/deploy.sh
- https://attack.mitre.org/techniques/T1036/004/
- https://github.com/CrowdStrike/logscale-community-content

The Microsoft blog's own hunting queries match tool names, hosts, hashes and fixed file names. This rule does not copy them and does not use any IOC as its trigger. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No rule in this repo matched this behaviour on main at 9a7a7d9 (searched for gsocket, exec -a, GS_ARGS, hidden temp-path execution and touch timestamp options).

## After
New crowdstrike rule DAC-CS-0246 on ProcessRollup2 (event_platform=Lin). Companion: DAC-MDE-0097.

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1036, T1036.004; tactics stealth.

## Existing overlap in this repo
None found.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| GS_HIDDEN_NAME set to a non-bracket name such as -bash or rsyslogd | deploy.sh and README allow any name | Covered in part by the GS_ARGS rule; known gap |
| exec -a hidden inside a script file | Only the script path is on the command line | Known gap; needs script content |
| Name set by prctl or argv overwrite after start | No new process event | Out of scope |

## Unverified
- Whether the Falcon Linux sensor CommandLine and the MDE ProcessCommandLine show the argv0 set by exec -a, or the real path. If they show the real path, only the exec -a branch (on the parent shell) fires.
- No real gsocket telemetry was available; fixtures are synthetic.
- Field names come from logscale-community-content Linux queries (ProcessRollup2, event_platform=Lin, UID, ParentBaseFileName, GrandParentBaseFileName, ImageFileName, CommandLine); query not run in LogScale.
- telemetry_validated false.

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0246/. Each has `"synthetic": true` and `result` "not run". There is no LogScale or Advanced Hunting runner here. As a supplement, the rule's regexes were mirrored in Python and applied to the fixture events. That checks the patterns only, not the query language.

| Fixture | Expect alert | Regex check | Result |
|---|---|---|---|
| malicious_0 | yes | would alert | match |
| malicious_1 | yes | would alert | match |
| benign_2 | no | no alert | match |
| near_miss_3 | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Draft argv0 regex excluded a slash inside the brackets, so names like [kworker/0:2] were missed | `CommandLine=[kworker/0:2] (malicious_1, second event)` | Allow any text except ] inside the brackets |
| 2 | Must | exec -a with any name would flag ordinary wrappers | `bash -c exec -a myapp /opt/myapp/bin/myapp (benign_2)` | Require a bracketed name after exec -a |
| 3 | Should | Bracket text inside a grep pattern | `bash -c ps aux | grep '[k]worker' (near_miss_3)` | argv0 branch anchors on the whole command line |

## Reviewer status
pending
