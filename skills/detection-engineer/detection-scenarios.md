# Detection scenario fluency

Hunt → detect → respond → learn for each family. Extend rows when you meet a new scenario in the wild.

## Host / endpoint

| Scenario | Hypothesis | Primary telemetry | High-fidelity anchors | Common FN traps |
|----------|------------|-------------------|----------------------|-----------------|
| LOLBin abuse | Living-off-land binary with technique flags | 4688, Sysmon 1 | basename + flag (`certutil`+`-encode`) | Cmdline-only; classic vs XML |
| Encoded PowerShell | `-EncodedCommand` / `-enc` process create | 4688, Sysmon 1, 4104 | proc + enc token; coalesce Image | Filter Image before coalesce |
| Script block | Malicious PS content in blocks | 4104 | ScriptBlockText patterns + length/entropy sparingly | Over-allowlist scripts |
| Persistence (service/task) | New service/task for foothold | 4698, 7045, Sysmon 1/11/13 | ImagePath + non-standard paths | Ignoring XML System channel |
| Credential access | LSASS / SAM dump patterns | Sysmon 10, 4662 | TargetImage + CallTrace / access mask | Alerting all handle opens |
| Defense evasion | Audit/policy disable, log clear | 4719, 1102, wevtutil cmdline | EventCode + actor | Missing Security channel |
| Lateral / logon | Explicit creds / unusual logon type | 4624/4625/4648, Sysmon 3 | LogonType + Workstation/IP | Broad 4624 without context |
| Persistence (registry) | Run keys / IFEO | Sysmon 13, Security registry | TargetObject path + Image | Missing Sysmon config |

## Cloud / identity

| Scenario | Hypothesis | Primary telemetry | High-fidelity anchors | Common FN traps |
|----------|------------|-------------------|----------------------|-----------------|
| Privilege + compute chain | PassRole then Lambda/EC2 abuse | CloudTrail | `eventName` + `requestParameters.*` + correlation | Single-API OR noise; wrong nested fields |
| IAM escalation | Attach/Put/Create policy anomalies | CloudTrail | eventName + policy ARN/doc | Ignoring AssumedRole issuer ARN |
| STS / federation abuse | Unusual AssumeRole / GetSessionToken | CloudTrail | userIdentity + sourceIP/userAgent | Hardcoded index only |
| Entra / AAD | Consent / app role / CA bypass | Entra audit | Operation + target resources | CIM rename without memory |

## Network / exfil staging

| Scenario | Hypothesis | Primary telemetry | High-fidelity anchors | Common FN traps |
|----------|------------|-------------------|----------------------|-----------------|
| DNS / C2 lite | Unusual DNS from LOLBins | Sysmon 22 | Image + QueryName | Alerting all browsers |
| Encode/archive staging | Large encode before exfil | 4688/Sysmon 1 | LOLBin + encode/archive flags | Substring `encode` alone |

## IR response fields (always ask)

For every alert path, ensure the query surfaces enough for triage:

- **Who:** user / ARN / SubjectUserName  
- **What:** process / eventName / technique tokens  
- **Where:** host / region / target resource ARN  
- **When:** `_time` + correlation window  
- **How far:** parent process, related eventNames, target function/instance  

If the alert cannot answer who/what/where, enrich before ship.

## Learning loop hook

After any scenario work: update `memory/sourcetypes/<family>.md`, append redacted note to `memory/log-context.md`, refresh `memory/field-confidence.md`.
