# REVIEW - DAC-MDE-0102 MDE: Side-load kit: one process writes an EXE, a DLL and config.ini into the same System32, SysWOW64 or ProgramData folder within 10 minutes

## Attribution
Clean-room behavioural rule written from public sources opened on 17 Nov 2026 (IST):
- https://securelist.com/operation-shadowcloud-graphdoor/122005/
- https://securelist.com/operation-shadowcloud-gitdoor/122004/
- https://attack.mitre.org/techniques/T1574/001/
- https://attack.mitre.org/techniques/T1036/005/
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table
- Telemetry questions were checked against vendor documentation (Microsoft Learn, Microsoft's published hunting queries, CrowdStrike's public logscale-community-content) before writing the query.

The Kaspersky reports list hashes, C2 addresses and SharePoint names. This rule uses none of them; it keys on behaviour. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No rule on main matched this behaviour at 8fd7c4f. The side-loading rules DAC-CS-0243, DAC-CS-0128, DAC-CS-0129, DAC-WIN-0171 and DAC-WIN-0083 all require the DLL in a user-writable path (Temp, AppData, Users, Public) or exclude System32, so the System32 drop described in Part 1 gets past them. DAC-WIN-0172 needs the writer to run from \users\ or \temp\.

## After
New defender rule DAC-MDE-0102 on DeviceFileEvents. It looks at the kit as a whole: one writer process, one folder, an EXE, a DLL and a file called config.ini within 10 minutes. No CrowdStrike companion: I could not find a public CrowdStrike source that says which Falcon file-write events cover a plain .ini file, so a Falcon version would rest on a guess.

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1574.001 (DLL; the v19.2 name, which covers side-loading), T1036.005, T1105. Tactics stealth, execution, command-and-control.

## Existing overlap in this repo
DAC-CS-0243 would fire for the Part 2 attribution case under ProgramData\excint if Falcon flags the DLL as unsigned. Nothing overlaps for System32.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Kit written by two different processes (for example the agent writes the EXE and a child writes the DLL) | Rule keys on one initiating process | Known gap |
| Payload file renamed away from config.ini | The report only shows config.ini; the name is a configurable detail | Known gap. Widening to any .ini or .dat would bring noise; revisit after a baseline |
| Kit dropped into Program Files or a user folder | Folder scope is System32, SysWOW64 and ProgramData | Program Files is out of scope here; user folders are covered in part by the existing side-load rules |
| Files staged more than 10 minutes apart | Window is 10 minutes | Window is an unmeasured starting point |

## Unverified
- Whether DeviceFileEvents records every FileCreated for .ini files in System32 and ProgramData. Microsoft does not publish its file-event collection rules.
- Whether a file copy (moveDir uses a copy) shows up as FileCreated in every case. The rule also accepts FileRenamed for moves.
- FolderPath content: the schema calls it the folder containing the file, while in practice it usually holds the full path. The query handles both.
- The servicing exclusion list is from my own knowledge of Windows servicing processes, not from a measured baseline.
- Query not run in Advanced Hunting. telemetry_validated false.
- No real ShadowCloud or GraphDoor telemetry was available; fixtures are synthetic. Thresholds and windows are unmeasured starting points.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0102/. Each has `"synthetic": true` and a `result` that says "not run". There is no Advanced Hunting runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_0 | yes | would alert | match |
| malicious_1 | yes | would alert | match |
| benign_2 | no | no alert | match |
| near_miss_3 | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | First draft summarised over the whole lookback, so a long-lived host process that wrote other EXEs into the same folder earlier would push the time span past 10 minutes and hide a later kit drop | `Earlier write at 08:00 then kit copy at 14:00 by the same PID` | Anchor on each config.ini write and join EXE and DLL writes within 600 seconds either side |
| 2 | Must | Grouping on InitiatingProcessId alone can merge two different processes that reused a PID during the day | `PID 4100 reused after a reboot` | Added InitiatingProcessCreationTime to the join keys |
| 3 | Should | parse_path(FolderPath).DirectoryPath gives the wrong folder if FolderPath already holds only the directory | `FolderPath=C:\ProgramData\VendorAgent` | Strip the file name only when FolderPath ends with it |
| 4 | Should | Moves (rename into place) would be missed | `Kit moved from Temp into ProgramData` | Accept FileRenamed as well as FileCreated |

## Reviewer status
pending
