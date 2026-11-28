# DAC-AZ-0014 review note

Status: tagged `needs-review` (2026-11-28). No logic change in this PR. ID kept, rule not deleted. `telemetry_validated: false`.

## Attribution
Public sources only, opened on 28 Nov 2026 (IST). No tenant data.
- Microsoft 5 Nov 2026 post (Key Vault secret reads after leaked-credential use): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- ThreatDefence ARTEX article (Key Vault SecretList / SecretGet; report row H7): https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Azure activity log ('These management operations are also called control plane operations'; 'Azure resource logs capture data plane operations ... getting a secret from a key vault'; 'The activity log doesn't typically capture read operations'): https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log
- Key Vault logging (AuditEvent category; 'All secret operations have the Secret<action> format, such as SecretGet and SecretListVersions'): https://learn.microsoft.com/en-us/azure/key-vault/general/logging
- Azure built-in permissions, Security (Microsoft.KeyVault/vaults/secrets/read 'View the properties of a secret, but not its value'; data action Microsoft.KeyVault/vaults/secrets/getSecret/action 'Gets the value of a secret'; no secrets/get/action): https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/security
- AZKVAuditLogs table: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azkvauditlogs
- splunk/attack_data T1555.006 (only aws_anomalous_secrets_manager_batch_retrieval; no Azure Key Vault payload): https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques/T1555.006

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). Report rows M14 and H7 classed this rule Partial.

```
(sourcetype=azure:monitor:activity OR sourcetype=azure:activity OR sourcetype=azure:insights:activitylogs)
| search operationName IN ("Microsoft.KeyVault/vaults/secrets/get/action","SecretGet","SecretList") OR operationName="*secrets*"
| table _time, operationName, caller, callerIpAddress, resourceId, status, activityStatusValue
```

## Issues
1. Wrong plane. SecretGet / SecretList are data-plane operation names. They are written to Key Vault resource logs (AuditEvent, AZKVAuditLogs in Sentinel), not to the activity log. On activity-log sourcetypes those two values should never match.
2. `Microsoft.KeyVault/vaults/secrets/get/action` is not a documented Key Vault operation. The documented data action is `.../secrets/getSecret/action`, and data actions are also not activity-log events.
3. `operationName="*secrets*"` will match control-plane secret writes and deletes (`Microsoft.KeyVault/vaults/secrets/write`, set via ARM templates), which is deployment noise, not secret reads.
4. Title says 'burst by unusual principal' but the query has no count, window, threshold or baseline.

## Decision: tag, do not move
Moving the logic to the data plane in this rule would mean writing a new Splunk search against a Key Vault diagnostic sourcetype. Repo rules say a Splunk query is only built from an attack_data payload, and there is no Key Vault AuditEvent payload in splunk/attack_data. The data-plane behaviour is already built as DAC-MDE-0116 (AZKVAuditLogs, list then 5+ secrets read, new caller). So this rule keeps its ID and query and is tagged `needs-review` with this note.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Read secrets on the data plane (the normal path) | T1555.006 | https://learn.microsoft.com/en-us/azure/key-vault/general/logging | not in activity log | n/a | covered elsewhere | DAC-MDE-0116 reads AZKVAuditLogs. |
| Read via ARM listKeys-style actions on other services | T1552 | https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log | yes | medium | out of scope | Separate report rows (M10-M12). |

## FP check
As written, the `*secrets*` wildcard will alert on ARM deployments that create or update secrets. That is the main expected noise. Not measured.

## Unverified ideas
- Splunk sourcetype for Key Vault AuditEvent via the Microsoft Cloud Services add-on (event hub input); not in config/sourcetype_map.yaml and not touched.
- Whether DAC-AZ-0039 (same query under a purge-protection title) should get the same tag in its own PR.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Data-plane names searched on a control-plane source | SecretGet in Key Vault AuditEvent | Tag; data-plane rule is DAC-MDE-0116 |
| 2 | Undocumented operation string | secrets/get/action | Noted; documented data action is getSecret/action |
| 3 | Wildcard matches ARM secret writes | Microsoft.KeyVault/vaults/secrets/write | Noted for the follow-up |
| 4 | No burst logic despite the title | one event | Noted |

## Tests / fixtures
None added. No logic change; fixtures would only test the current mismatch.

## Suggested follow-up (separate PR, needs approval)
- Either retire the Splunk query in favour of DAC-MDE-0116, or rewrite it on a Key Vault diagnostic sourcetype once an attack_data payload (or a public sample) exists, with count/window/novelty logic.
- Narrow or drop `operationName="*secrets*"`.

## Reviewer status
- pending human approval
