# REVIEW - DAC-MDE-0103 MDE: Process creates a named pipe called \p followed by its own process ID

## Attribution
Clean-room behavioural rule written from public sources opened on 17 Nov 2026 (IST):
- https://securelist.com/operation-shadowcloud-graphdoor/122005/
- https://attack.mitre.org/techniques/T1559/
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table
- https://github.com/Azure/Azure-Sentinel/blob/863e9128d3fbcda27fc2ce54a9cd00b7c61d155e/Hunting%20Queries/Microsoft%20365%20Defender/Command%20and%20Control/C2-NamedPipe.yaml
- Telemetry questions were checked against vendor documentation (Microsoft Learn, Microsoft's published hunting queries, CrowdStrike's public logscale-community-content) before writing the query.

The Kaspersky reports list hashes, C2 addresses and SharePoint names. This rule uses none of them; it keys on behaviour. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No rule on main matched this behaviour at 9f39fd4. DAC-WIN-0188 only covers fixed psexec, remcom, paexec and winrm pipe names.

## After
New defender rule DAC-MDE-0103 on DeviceEvents (NamedPipeEvent). The ActionType and the AdditionalFields keys (PipeName, FileOperation, NamedPipeEnd) come from Microsoft's own published hunting queries, because the Learn schema page does not list them. No CrowdStrike companion: Falcon's NamedPipeDetectInfo has a PipeName field, but public sources don't say whether it fires for every pipe creation or only for pipes the sensor flags, so a Falcon version could be silent and look like coverage.

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1559 (Inter-Process Communication), tactic execution. T1559.001 is COM and T1559.002 is DDE, so neither sub-technique fits a named pipe; the parent is used.

## Existing overlap in this repo
None found.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Pipe name scheme changed (different prefix or a random name) | Rule depends on the p-plus-PID construction | Known gap; the construction is what makes this low-noise |
| Pipe created by a helper process and used by the backdoor | Creator PID differs from the name | Would not fire (near_miss_3 shows this). Known gap |
| NamedPipeEvent capped or sampled by MDE | Unknown collection limits | Unverified; see below |

## Unverified
- Whether MDE caps or samples NamedPipeEvent. Microsoft doesn't publish this.
- The exact PipeName format. Public examples show a \Device\NamedPipe\ prefix; ends-with handles either form.
- Whether InitiatingProcessId on NamedPipeEvent is always the creating process. That's how the column is defined for DeviceEvents, but it hasn't been tested here.
- Sysmon note for Splunk users (not part of this rule): the SwiftOnSecurity config only logs listed pipe names and would miss this, while Olaf Hartong's sysmon-modular logs all pipe creations.
- Query not run in Advanced Hunting. telemetry_validated false.
- No real ShadowCloud or GraphDoor telemetry was available; fixtures are synthetic. Thresholds and windows are unmeasured starting points.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0103/. Each has `"synthetic": true` and a `result` that says "not run". There is no Advanced Hunting runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_0 | yes | would alert | match |
| malicious_1 | yes | would alert | match |
| benign_2 | no | no alert | match |
| near_miss_3 | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | An exact-equality match on '\\p'+PID misses the \Device\NamedPipe\ prefix | `PipeName=\Device\NamedPipe\p6412 (malicious_0)` | Use endswith on the PID-built suffix |
| 2 | Must | Clients connecting to an existing pipe would also match the name | `FileOperation=File opened (near_miss_3)` | Require FileOperation == "File created" |
| 3 | Should | Endswith alone could match a longer number such as \p14120 for PID 4120 | `PID 4120, pipe \p14120` | The suffix includes the backslash and the p, so \p4120 is not a suffix of \p14120 |

## Reviewer status
pending
