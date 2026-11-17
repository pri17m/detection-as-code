# REVIEW - DAC-MDE-0105 MDE: cmd.exe started by a binary in System32 or SysWOW64 that is not Microsoft-signed

## Attribution
Clean-room behavioural rule written from public sources opened on 17 Nov 2026 (IST):
- https://securelist.com/operation-shadowcloud-graphdoor/122005/
- https://securelist.com/operation-shadowcloud-gitdoor/122004/
- https://attack.mitre.org/techniques/T1059/003/
- https://attack.mitre.org/techniques/T1036/005/
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefilecertificateinfo-table
- Telemetry questions were checked against vendor documentation (Microsoft Learn, Microsoft's published hunting queries, CrowdStrike's public logscale-community-content) before writing the query.

The Kaspersky reports list hashes, C2 addresses and SharePoint names. This rule uses none of them; it keys on behaviour. No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic.

## As-is (new)
No Defender rule on main matched this behaviour at 0eadd98. DAC-MDE-0002, 0032, 0080 and 0081 look at specific parent sets (Office and others) that don't include these hosts.

## After
New defender rule DAC-MDE-0105 on DeviceProcessEvents joined to DeviceFileCertificateInfo. No CrowdStrike companion: Falcon's public SignInfoFlags query decodes the flags of the process's own image on ProcessRollup2, not its parent's, so a Falcon version would need a self-join I can't check against public docs. DAC-CS-0084 already covers rare cmd.exe parents on Falcon.

## ATT&CK v19.2
Checked against enterprise-attack-19.2.json: T1059.003 (Windows Command Shell), T1036.005 (Match Legitimate Resource Name or Location). Tactics execution, stealth.

## Existing overlap in this repo
DAC-CS-0084 (Falcon, rarity-based) would likely fire on the same activity.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Side-load host is a genuinely Microsoft-signed EXE | The host binary is trusted; only the DLL is malicious | Known gap; the DLL is the malicious part and this rule looks at the parent EXE |
| Command run through powershell.exe or a direct API instead of cmd.exe | Rule keys on cmd.exe | Known gap |
| Parent outside System32/SysWOW64 (ProgramData) | Folder scope | ProgramData parents would be too noisy here; the kit-drop rule DAC-MDE-0102 covers ProgramData |
| No certificate row and a forged Microsoft company name | Unknown branch trusts the company name | Known gap until DeviceFileCertificateInfo has the SHA1 |

## Unverified
- How quickly and how completely DeviceFileCertificateInfo gets a row for a newly dropped binary. Microsoft says it comes from regular certificate verification activity and doesn't say which files or how often.
- IsRootSignerMicrosoft semantics for catalog-signed in-box binaries. The schema says it covers files included in Windows, but this hasn't been tested.
- InitiatingProcessSignerType and InitiatingProcessSignatureStatus exist in DeviceProcessEvents, but their values aren't documented, so the rule doesn't use them.
- Query not run in Advanced Hunting. telemetry_validated false.
- No real ShadowCloud or GraphDoor telemetry was available; fixtures are synthetic. Thresholds and windows are unmeasured starting points.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0105/. Each has `"synthetic": true` and a `result` that says "not run". There is no Advanced Hunting runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_0 | yes | would alert | match |
| malicious_1 | yes | would alert | match |
| benign_2 | no | no alert | match |
| near_miss_3 | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Dropping parents by version-info company before the certificate join lets a forged 'Microsoft Corporation' company hide a non-Microsoft binary | `malicious_1 second check: company=Microsoft Corporation, signer=PSF` | Apply the company test only to the no-certificate branch |
| 2 | Must | A missing certificate row was treated as unsigned, which flags every Microsoft binary that hasn't been verified yet | `svchost.exe with no row` | Treat a missing row as unknown and require a non-Microsoft company name in that branch |
| 3 | Should | Duplicate certificate rows per SHA1 multiply alert rows | `Two rows for one SHA1` | arg_max by SHA1 before the join |
| 4 | Should | Column name collision on SHA1 after the join | `DeviceProcessEvents.SHA1 vs DeviceFileCertificateInfo.SHA1` | Rename to CertSHA1 inside the Certs subquery |

## Reviewer status
pending
