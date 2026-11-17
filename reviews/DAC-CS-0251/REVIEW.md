# REVIEW - DAC-CS-0251 Falcon: Falcon: winpty-agent.exe runs from a temp folder

## Attribution
Clean-room behavioural rule written from public sources opened on 17 Nov 2026 (IST):
- https://securelist.com/operation-shadowcloud-gitdoor/122004/
- https://securelist.com/operation-shadowcloud-graphdoor/122005/
- https://github.com/rprichard/winpty
- https://attack.mitre.org/techniques/T1059/003/
- https://github.com/CrowdStrike/logscale-community-content
- Telemetry questions were checked against vendor documentation (Microsoft Learn, Microsoft's published hunting queries, CrowdStrike's public logscale-community-content) before writing the query.

The Kaspersky reports list hashes, C2 addresses and SharePoint names. This rule uses none of them; it keys on behaviour. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No rule on main matched this behaviour at 4bd648a (searched detections/ for winpty).

## After
New crowdstrike rule DAC-CS-0251 on ProcessRollup2 (ImageFileName, CommandLine, ParentBaseFileName; field names as used in CrowdStrike's public logscale-community-content queries). Companion: DAC-MDE-0104.

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1059.003, T1105. Tactics execution, command-and-control.

## Existing overlap in this repo
DAC-CS-0084 (cmd.exe from a rare parent) may fire on the shell the agent starts; it doesn't look at the agent itself.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| winpty-agent.exe renamed | Rule keys on the image name | Known gap |
| Agent start not in ProcessRollup2 but child is | No parent path field used here | Known gap; the MDE companion covers it |
| Dropped outside Temp | Path scope is the two temp folders | Known gap |

## Unverified
- Falcon ImageFileName format (\Device\HarddiskVolumeN\ prefix). The regexes don't depend on the drive prefix.
- Whether any common software unpacks winpty-agent.exe to %TEMP% at run time.
- Query not run in LogScale. telemetry_validated false.
- No real ShadowCloud or GraphDoor telemetry was available; fixtures are synthetic. Thresholds and windows are unmeasured starting points.

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0251/. Each has `"synthetic": true` and a `result` that says "not run". There is no LogScale runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_0 | yes | would alert | match |
| malicious_1 | yes | would alert | match |
| benign_2 | no | no alert | match |
| near_miss_3 | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | A contains-style match on 'winpty' would hit installers and other files | `winpty-agent-setup.exe in Temp (near_miss_3)` | Anchor the name: \\winpty-agent\.exe$ |
| 2 | Should | Drive-letter based path regex breaks on the \Device\HarddiskVolume form | `ImageFileName=\Device\HarddiskVolume3\Users\...` | Regex matches the folder segment only |

## Reviewer status
pending
