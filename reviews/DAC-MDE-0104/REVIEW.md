# REVIEW - DAC-MDE-0104 MDE: winpty-agent.exe runs from a temp folder, or a temp-folder winpty-agent starts a process

## Attribution
Clean-room behavioural rule written from public sources opened on 17 Nov 2026 (IST):
- https://securelist.com/operation-shadowcloud-gitdoor/122004/
- https://securelist.com/operation-shadowcloud-graphdoor/122005/
- https://github.com/rprichard/winpty
- https://attack.mitre.org/techniques/T1059/003/
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- Telemetry questions were checked against vendor documentation (Microsoft Learn, Microsoft's published hunting queries, CrowdStrike's public logscale-community-content) before writing the query.

The Kaspersky reports list hashes, C2 addresses and SharePoint names. This rule uses none of them; it keys on behaviour. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No rule on main matched this behaviour at db5aa24 (searched detections/ for winpty).

## After
New defender rule DAC-MDE-0104 on DeviceProcessEvents with two branches: the agent itself starting from a temp folder, or a temp-folder agent starting a child. Companion: DAC-CS-0251 (agent branch only).

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1059.003 (Windows Command Shell), T1105 (Ingress Tool Transfer, for the dropped WinPTY files). Tactics execution, command-and-control.

## Existing overlap in this repo
None found.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| winpty-agent.exe renamed | Rule keys on the file name | Known gap. The report only names winpty-agent.exe; a hash or version-info match would need real samples |
| Dropped somewhere other than Temp (for example ProgramData) | Path scope is the two temp folders | Known gap; the report says %TEMP% |
| ConPTY used instead of WinPTY | Different mechanism, no agent binary | Out of scope |

## Unverified
- Whether any common software unpacks winpty-agent.exe to %TEMP% at run time.
- Whether %TEMP% resolves to a path other than AppData\Local\Temp on managed builds (redirected profiles).
- Query not run in Advanced Hunting. telemetry_validated false.
- No real ShadowCloud or GraphDoor telemetry was available; fixtures are synthetic. Thresholds and windows are unmeasured starting points.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0104/. Each has `"synthetic": true` and a `result` that says "not run". There is no Advanced Hunting runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_0 | yes | would alert | match |
| malicious_1 | yes | would alert | match |
| benign_2 | no | no alert | match |
| near_miss_3 | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Agent start events can be missed when the agent is short-lived or sampled, leaving only its child | `Only cmd.exe with a temp-folder winpty-agent parent (malicious_1)` | Added the parent branch on InitiatingProcessFolderPath |
| 2 | Should | Matching any path containing 'Temp' would hit folders like C:\Templates | `FolderPath=C:\Users\u\Templates\winpty-agent.exe` | Regex needs \AppData\Local\Temp\ or \Windows\Temp\ as a full path segment |

## Reviewer status
pending
