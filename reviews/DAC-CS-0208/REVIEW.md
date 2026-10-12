# REVIEW — DAC-CS-0208 Java server process spawning shell or LOLBin (Log4Shell-style)

## Coverage before
ProcessRollup2/ProcessBlocked with ParentBaseFileName java/javaw and child cmd|powershell|pwsh|bash|sh|curl|wget|certutil|mshta, selfJoinFilter with NetworkConnectIP4 from the child to ports 1389/1099/389/636.

## Coverage after
Same, plus Windows child ImageFileName endings `wscript|cscript|regsvr32|bitsadmin`. Network join unchanged (keeps precision).

## ATT&CK mapping check (v19.2)
- T1190 — correct framing for Log4Shell-class JNDI exploitation. https://attack.mitre.org/techniques/T1190/
- T1059 — correct. https://attack.mitre.org/techniques/T1059/
Reference https://logging.apache.org/log4j/2.x/manual/lookups.html documents JNDI lookups used in the exploit class.

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| java → wscript/cscript/regsvr32/bitsadmin + LDAP/RMI net | T1190 / T1059 | Sigma proc_creation_win_java_susp_child_process (includes wscript/cscript/regsvr32/bitsadmin); Sigma proc_creation_lnx_susp_java_children; Sigma proc_creation_win_java_susp_child_process_2 (shells) | yes | medium → tightened | tightened | Network join to 1389/1099/389/636 is the tightening that keeps installers from firing. |
| java → python | T1059 | Sigma lnx java children includes python | yes | high | dropped | Many JVM ops shell to python; untightenable without app allowlists. |
| JNDI to non-listed ports | T1190 | Log4Shell variants | yes | medium | dropped | Expanding ports loses the Log4Shell-style precision; belongs in a broader java-shell rule. |

## Unverified ideas
- Correlate DnsRequest for `${jndi:` patterns (needs application log source).

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.

## Reviewer status: pending human approval
