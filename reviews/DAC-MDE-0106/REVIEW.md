# REVIEW - DAC-MDE-0106 MDE: Java or Tomcat service-account process starts cmd or PowerShell

## Attribution
Clean-room behavioural rule written from public sources opened on 19 Nov 2026 (IST):
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- https://tomcat.apache.org/tomcat-9.0-doc/windows-service-howto.html
- https://attack.mitre.org/techniques/T1190/
- https://attack.mitre.org/techniques/T1059/003/
- https://attack.mitre.org/techniques/T1059/001/
- https://attack.mitre.org/techniques/T1685/
- https://community.fortinet.com/fortiedr-20/threat-coverage-how-fortiedr-protects-against-confluence-cve-2022-26134-post-exploitation-activity-109660
- https://www.vulncheck.com/blog/confluence-dreams-of-shells
- https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/
- SigmaHQ (reference only, not a conversion): dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0, 8202070f-edeb-4d31-a010-a26c72ac5600, 1ddaa9a4-eb0b-4398-a9fe-7b018f9e23db
- Java4Shell context (confirmed vulnerability, not used as the match logic): https://openjdk.org/groups/vulnerability/advisories/2026-11-17 , https://www.oracle.com/security-alerts/cspunov2026.html , https://nvd.nist.gov/vuln/detail/CVE-2026-114938 , https://www.cve.org/CVERecord?id=CVE-2026-114938 , https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching , https://cert.europa.eu/publications/security-advisories/2026-021/

No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic. The rule does not use process names, service names, PIDs or paths from a process-tree screenshot that was shown while this rule was being scoped.

## As-is (new)
No rule on main at 70057c70 mentioned java.exe, javaw.exe, tomcat or Confluence. Closest coverage:
- DAC-MDE-0096 / DAC-CS-0245 / DAC-WIN-0365: PHP or IIS worker (apache2, httpd, php-fpm, php-cgi, php.exe, w3wp.exe) spawning a shell, and only when two behaviour classes (recon, download, revshell, temp-exec) appear in 10 minutes. That parent list does not include Java or Tomcat, and the class stack would miss a simple `cmd /c` first hop.
- DAC-CS-0084: rare cmd/powershell parent on Falcon. Rarity-based, not a fixed Java/Tomcat parent list, and Falcon only.
- DAC-MDE-0105: cmd.exe started by a non-Microsoft-signed binary under System32 or SysWOW64. Tomcat lives under Program Files, so it is out of scope.
- DAC-MDE-0079, DAC-MDE-0045, DAC-MDE-0046, DAC-CS-0224, DAC-CS-0242, DAC-WIN-0070, DAC-WIN-0153, DAC-WIN-0192, DAC-WIN-0082: Defender tamper (Add-MpPreference, Set-MpPreference, registry, service stop). They can catch a later Defender-disable step but not the Java or Tomcat parent starting a shell.
- DAC-WIN-0223: Sysmon network 5985/5986 from a non-Network-Service account. Different behaviour.

## After
New defender rule DAC-MDE-0106 on DeviceProcessEvents. Parent is java.exe, javaw.exe, tomcat plus optional digits plus .exe, or prunsrv.exe, or a parent command line with the Commons Daemon `//RS//` run-service switch. The parent must be NETWORK SERVICE or LOCAL SERVICE, matched first by SID (S-1-5-20, S-1-5-19) and then by account name, including the no-space forms. Child is cmd.exe, powershell.exe or pwsh.exe. A `\Jenkins\` path exclusion is the only CI filter. No CrowdStrike or Splunk companion in this PR.

## ATT&CK v19.2
T1190 (Exploit Public-Facing Application), T1059.003 (Windows Command Shell), T1059.001 (PowerShell). Tactics initial-access, execution. T1685 (Disable or Modify Tools, Defense Impairment) is the v19 successor of T1562.001 and is already used on the Defender-tamper rules above; this rule does not key on Defender tamper, so T1685 is not tagged. T1068 / T1134 would apply to a service-account parent whose child runs as SYSTEM; that account-change is not part of this query.

## Existing overlap in this repo
See As-is. Nothing on main matches this parent and account combination.

## Why the parent list is wider than java.exe
Tomcat's Windows service howto documents StartMode=jvm as starting Java in-process inside tomcat9.exe, and `//RS//` as the switch used when Service Manager runs the service. The same page says the service binary can be renamed to match a custom service name, which is why `//RS//` is also a parent condition. Fortinet's CVE-2022-26134 write-up says a Windows Confluence install is an Apache Tomcat 9 process named tomcat9.exe and that it runs as `nt authority\network service`; they hunt process-creation events from that parent because Confluence does not normally start LOLBins. VulnCheck's CVE-2023-22527 notes show a Windows `whoami` result of `nt authority\network service` and public exploits that start `cmd.exe /c powershell.exe`. Volexity's CVE-2022-26134 report is a Linux case (Confluence process spawning bash) and is cited only for the "web process starts a shell" behaviour.

SigmaHQ is cited as prior art, not as a conversion:
- dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0 matches a shell child of java.exe only, and excludes paths or command lines containing `build`. It misses tomcat9.exe.
- 8202070f-edeb-4d31-a010-a26c72ac5600 includes `\tomcat.exe` (does not match tomcat9.exe), `ws_TomcatService.exe`, and java.exe/javaw.exe when the path contains tomcat or the command line has CATALINA_HOME.
- 1ddaa9a4-eb0b-4398-a9fe-7b018f9e23db matches tomcat8/9/10.exe but also requires `confluence` in the parent command line, and is scoped to one CVE.

## Java4Shell (CVE-2026-114938) — confirmed advisory, unverified in-the-wild use
The CVE exists. Oracle is the CNA. It is in the 17 Nov 2026 OpenJDK advisory (hotspot/compiler, CVSSv3.1 8.1, affects 17/21/25/27, not 8 or 11 in that matrix), the November 2026 Oracle Critical Security Patch Update (Java SE and GraalVM listed; Quang Luong of Calif.io and Albert Yang acknowledged), NVD (source secalert_us@oracle.com, status Undergoing Analysis, same 8.1 vector, no cisaExploitAdd), and CVE.org (PUBLISHED, datePublished 2026-11-17T21:32:03.183Z). CISA issued a patch alert the same day and called it Java4Shell; CERT-EU advisory 2026-021 (18 Nov 2026) describes the Base64-decoder intrinsic, the CPU conditions, and the stopgap `-XX:+UnlockDiagnosticVMOptions -XX:-UseBASE64Intrinsics` or `-XX:UseAVX=2`. In OpenJDK `src/hotspot/share/runtime/globals.hpp`, `UseBASE64Intrinsics` is a product flag (not DIAGNOSTIC), so `-XX:-UseBASE64Intrinsics` on its own is a valid switch; CERT-EU still prefixes UnlockDiagnosticVMOptions. Atlassian had a Data Center mitigations post for this CVE (community thread, `-XX:UseAVX=2`), but no dedicated advisory was found on https://www.atlassian.com/trust/security/advisories while this review was written.

The CVE is not in the CISA KEV catalog JSON retrieved on 19 Nov 2026 (0 hits for 2026-114938). A social post and a process-tree screenshot claimed live exploitation against Confluence. That claim is not treated as fact here. The rule is written so it would still apply to the next Java or Confluence RCE that shells out from the service process.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Service runs as a custom account or as SYSTEM | Account filter is only NETWORK SERVICE and LOCAL SERVICE | Known gap. SYSTEM would catch more installs and more noise (installers, scheduled Java jobs). Custom service accounts are common on Confluence. |
| First child is not cmd, powershell or pwsh (direct payload exe) | Child filter | Known gap. The observed first hop in similar Confluence cases has been a shell. |
| Procrun binary renamed and the command line does not contain `//RS//` | Name plus switch coverage | Reduced by the `//RS//` condition. Remaining gap if both the name and the switch are absent. |
| tomcat9w.exe (the GUI monitor) | Parent regex is `^tomcat[0-9]*\.exe$`, which excludes the `w` suffix | Intended. The monitor is not the service. |
| StartMode=Java or exe where the child of the wrapper is java.exe, and java.exe then starts a shell as a non-service account | Account filter | The java.exe parent still matches when that java.exe is NETWORK SERVICE or LOCAL SERVICE. |
| Shell started by a grandchild (wrapper -> java -> cmd is a direct java parent; deeper trees are not walked) | No ancestor walk | Known gap past one parent. InitiatingProcessParentFileName is projected for triage only. |
| Jenkins path spelling that does not contain `\Jenkins\` | Exclusion is path-based | Documented FP. |

## Unverified
- Whether DeviceProcessEvents always fills InitiatingProcessAccountSid in every tenant. The name fallback is there for that case; localised account names other than the English and no-space forms are unverified.
- Whether every renamed Tomcat or Confluence procrun service keeps `//RS//` on the running process command line.
- Query not run in Advanced Hunting. telemetry_validated false.
- In-the-wild exploitation of CVE-2026-114938, including the Confluence process tree that prompted this work. Not in CISA KEV as of the 19 Nov 2026 catalog fetch.
- False-positive rate for Artifactory, Jira, Keycloak, TeamCity and similar Java services running as NETWORK SERVICE.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0106/. Each has `"synthetic": true` and a `result` that says "not run". There is no Advanced Hunting runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_tomcat9_networkservice_cmd | yes | would alert | match |
| malicious_java_localservice_powershell | yes | would alert | match |
| malicious_renamed_procrun_rs_switch | yes | would alert | match |
| benign_interactive_java_user_cmd | no | no alert | match |
| near_miss_w3wp_networkservice_cmd | no | no alert | match |
| near_miss_tomcat9w_monitor | no | no alert | match |
| near_miss_jenkins_path | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | A parent list that only has java.exe misses Confluence/Tomcat on Windows, because StartMode=jvm runs the JVM inside tomcat9.exe | `tomcat9.exe (NETWORK SERVICE) starts cmd.exe` | Include `tomcat[0-9]*.exe` and prunsrv.exe |
| 2 | Must | Sigma-style `endswith tomcat.exe` does not match tomcat9.exe or tomcat10.exe | `C:\...\tomcat9.exe` | Match `^tomcat[0-9]*\.exe$` |
| 3 | Must | Account name "NETWORK SERVICE" is locale-dependent | German or other localised service account name, SID still S-1-5-20 | Prefer InitiatingProcessAccountSid S-1-5-19/20, keep English and no-space names as fallback |
| 4 | Must | Requiring stacked recon/download command-line classes, as in DAC-MDE-0096, misses a simple first hop | `cmd.exe /c cd /d C:\Program Files\...` | Alert on the parent, account and shell child alone |
| 5 | Should | Jenkins java.exe running as NETWORK SERVICE starts cmd often | `C:\Program Files\Jenkins\...java.exe -> cmd.exe` | Exclude folder paths containing `\Jenkins\` |
| 6 | Should | Tomcat docs allow renaming the service binary, so a hard-coded tomcat9.exe parent misses those installs | `custom-named procrun exe //RS//ServiceName starts cmd.exe` | Also match InitiatingProcessCommandLine containing `//RS//` |
| 7 | Should | tomcat9w.exe is the GUI monitor, not the service | `tomcat9w.exe` | Regex requires optional digits only, so the `w` suffix does not match |

## Reviewer status
pending
