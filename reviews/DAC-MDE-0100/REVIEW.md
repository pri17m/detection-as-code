# REVIEW - DAC-MDE-0100 MDE: Linux execution of a dot-hidden file or folder under /dev/shm, /tmp, /var/tmp or /run/user

## Attribution
Clean-room behavioural rule written from public sources opened on 12 Nov 2026 (IST):
- https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
- https://attack.mitre.org/techniques/T1564/001/
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table

The Microsoft blog's own hunting queries match tool names, hosts, hashes and fixed file names. This rule does not copy them and does not use any IOC as its trigger. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No rule in this repo matched this behaviour on main at 9a7a7d9 (searched for gsocket, exec -a, GS_ARGS, hidden temp-path execution and touch timestamp options).

## After
New defender rule DAC-MDE-0100 on DeviceProcessEvents. Companion: DAC-CS-0249.

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1564.001; tactics stealth.

## Existing overlap in this repo
None found.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Non-hidden name in /tmp such as /tmp/systemd-remount-d | No leading dot | Known gap; blog shows this name too |
| Hidden copy in /usr/bin or ~/.config | Outside temp roots | deploy.sh prefers these; covered by the kernel-name and GS_ARGS rules |
| memfd or deleted-file execution | Path not on disk | Out of scope |

## Unverified
- That DeviceProcessEvents FolderPath on Linux holds the full path including the file name (MS Learn says the folder containing the file; the Windows behaviour includes the file name). The query works either way for a hidden folder, but a hidden file in /tmp itself needs the file name in the path or the FileName check.
- Volume of dot-folder execution in /tmp on build hosts.
- Field names come from the MS Learn DeviceProcessEvents schema page; query not run in Advanced Hunting.
- telemetry_validated false.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0100/. Each has `"synthetic": true` and `result` "not run". There is no LogScale or Advanced Hunting runner here. As a supplement, the rule's regexes were mirrored in Python and applied to the fixture events. That checks the patterns only, not the query language.

| Fixture | Expect alert | Regex check | Result |
|---|---|---|---|
| malicious_0 | yes | would alert | match |
| malicious_1 | yes | would alert | match |
| benign_2 | no | no alert | match |
| near_miss_3 | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Draft only covered /dev/shm/. | `/tmp/.gsn_ora (malicious_1)` | Add /tmp, /var/tmp, /run/user/<uid> |
| 2 | Must | Draft fired on AppImage | `/tmp/.mount_ObsidiX1/obsidian (near_miss_3)` | Exclude /.mount_ |
| 3 | Should | Non-hidden temp binaries | `/tmp/installer/setup (near_miss_3)` | Require a dot segment |

## Reviewer status
pending
