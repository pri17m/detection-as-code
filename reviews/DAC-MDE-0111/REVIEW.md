# REVIEW - DAC-MDE-0111 MDE: WinRM fan-out to many hosts, private ranges included

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence published an example WinRM fan-out hunt (Hunt 16); this rule adds a 14-day first-seen baseline per device, keeps a separate private-target count, and wraps the source in a function. No query text was copied.
- ThreatDefence (ARTEX lateral movement: nmap for WinRM on 5985/5986, then Evil-WinRM, Impacket PsExec, NetExec; Hunt 16 WinRM fan-out): https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (ARTEX context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- DeviceNetworkEvents (Defender XDR): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table ; Azure Monitor copy: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicenetworkevents (RemoteIPType values include Public, Private, Loopback)
- ConnectionSuccess ActionType used in Microsoft's own advanced hunting examples: https://learn.microsoft.com/en-us/defender-endpoint/investigate-behind-proxy
- WinRM default ports 5985 (HTTP) and 5986 (HTTPS): https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management
- Atomic Red Team T1021.006 (Invoke-Command 5295bd61-bd7e-4744-9d52-85962a4cf2d6, Evil-WinRM efe86d95-44c4-4509-ae42-7bfd9d1f5b3d): https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md
- ATT&CK v19.2: T1021.006 Windows Remote Management (lateral-movement). https://attack.mitre.org/techniques/T1021/006/

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence Hunt 16c was a Gap. DAC-CS-0064 (Falcon, ByteRay Query-Hub MIT adaptation) matches NetworkConnectIP4 on 445/3389/5985 but excludes 10/8, 172.16/12, 192.168/16 and 127/8, and has no per-source target count. It is a generic outbound lateral-movement query, so it was not rewritten: changing its intent would break its attribution and its 445/3389 coverage. DAC-WIN-0223 (Sysmon 5985/5986 from a non-NETWORK SERVICE account) is a single-connection rule, not fan-out.

## After
New defender rule DAC-MDE-0111: per device, distinct WinRM RemoteIP in 10-minute bins, 10 or more, and no such bin for that device in the previous 14 days. CS-0064 is left unchanged (never delete). A Falcon companion can follow in its own PR if wanted.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Fan out from a management server that already does daily WinRM fan-out | T1021.006 | https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting | yes | n/a | known gap | The baseline excludes it by design. |
| Slow fan-out (under 10 targets per 10 minutes) | T1021.006 | https://attack.mitre.org/techniques/T1021/006/ | yes | n/a | known gap | Threshold trade-off. |
| WinRM on a non-default port | T1021.006 | https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management | yes | unknown | not added | The page documents configurable listeners; port-agnostic detection would need wsmprovhost or process context on the target. |
| Attacker host is not onboarded to MDE (Linux box running Evil-WinRM) | T1021.006 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md | no on source | n/a | not detectable here | Target-side view would need inbound events or 4624 type 3 + wsmprovhost on each target. |
| Use SMB/PsExec or RDP instead | T1021.002 / T1021.001 | https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting | yes | n/a | out of scope | Separate rules. |
| nmap scan of 5985/5986 that mostly fails | T1046 | https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting | yes | medium | dropped from this rule | ConnectionFailed bursts are scanning, a different behaviour with more noise (vuln scanners). Near-miss fixture covers it. |

## Unverified ideas
- Target-side companion: many inbound 5985/5986 sessions from one internal source across hosts (needs InboundConnectionAccepted volume testing).
- Whether ConnectionSuccess is emitted for every WinRM session in all MDE sensor versions.
- Advanced Hunting keeps 30 days; the 15-day total lookback fits, but a Sentinel copy may need TimeGenerated instead of Timestamp.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0111/ (synthetic, not run). `_phase` marks baseline vs recent events for the Python mirror; it is not a table column.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_workstation_winrm_to_15_private_hosts | yes | alert | match |
| malicious_mixed_5985_5986 | yes | alert | match |
| benign_known_management_server | no | no alert | match |
| near_miss_nine_targets | no | no alert | match |
| near_miss_failed_connections_scan | no | no alert | match |
| near_miss_spread_over_an_hour | no | no alert | match |

CI validate: see PR checks. Not run in Advanced Hunting.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Dropping RFC1918 (as DAC-CS-0064 does) removes the main lateral-movement case | 15 internal 10.x hosts on 5985 | No private-range filter; private count shown as context |
| 2 | Counting connections instead of distinct targets alerts on one chatty session | 200 connections to one host | `dcount(RemoteIP)` |
| 3 | Management servers fan out every day | mgmt01 with 40 targets daily | 14-day leftanti baseline on DeviceId |
| 4 | Loopback WinRM (Invoke-Command against localhost) is not fan-out | RemoteIP 127.0.0.1 | `RemoteIPType != "Loopback"` |
| 5 | Defining the source twice risks the baseline and live filters drifting apart | edit one copy only | One `WinRmConnects` function used for both |

## Reviewer status
- pending human approval
