# REVIEW - DAC-MDE-0122 Sentinel: ARM deployments/validate sweep by a new caller

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence Hunt 15 counts validate rows per caller and IP per minute (>= 5); this rule counts calls (distinct correlation IDs or deployment IDs) so status rows do not inflate the count, and adds a 14-day per-caller baseline. No query text was copied.
- Google Threat Intelligence Group, ARTEX and Friends ('an 8-second ARM deployments/validate dry-run sweep across 11 Azure resource types'): https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- ThreatDefence Hunt 15 (validate sweep; report row H15b): https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (ARTEX context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- Operation string verified: `Microsoft.Resources/deployments/validate/action` - 'Validates a deployment.' (Azure built-in permissions, Management and governance, Microsoft.Resources): https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/management-and-governance
- Deployments - Validate REST API (POST .../providers/Microsoft.Resources/deployments/{deploymentName}/validate): https://learn.microsoft.com/en-us/rest/api/resources/deployments/validate
- Activity log scope ('Entries typically result from changes (create, update, and delete operations) or an action being initiated. The activity log doesn't typically capture read operations.'): https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log
- AzureActivity schema (OperationNameValue, Caller, CallerIpAddress, CorrelationId 'Events that share a correlationId belong to the same uber action', ActivityStatusValue, ResourceGroup, SubscriptionId, _ResourceId): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity
- ATT&CK v19.2 T1580 Cloud Infrastructure Discovery (discovery): https://attack.mitre.org/techniques/T1580/

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence H15b was a Gap, and the report said to confirm the operation string before building. It is now confirmed on Learn (link above). Whether a validate call reaches AzureActivity was not seen on a sample; Learn says actions are recorded and reads typically are not, and validate is a POST action.

## After
New defender (Sentinel KQL) rule DAC-MDE-0122. 5+ distinct validate calls by one caller in 2 minutes; callers that already burst in the prior 14 days are dropped. Same-hour deployments/write count is a context column.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Use what-if (Microsoft.Resources/deployments/whatIf/action) instead of validate | T1580 | https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/management-and-governance | yes | unknown | known gap | Listed next to validate on the same Learn page; a sibling rule could add it after checking noise. |
| One validate call with a template that holds all 11 resource types | T1580 | https://learn.microsoft.com/en-us/rest/api/resources/deployments/validate | yes | n/a | known gap | One call, one count. GTIG saw a sweep of many calls; a single large template would need Properties parsing (not verified). |
| Slow the sweep past 2 minutes | T1580 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | yes | higher | known gap | Window fits the 8-second observation with room. |
| Use a caller that already bursts validations (pipeline identity) | T1078.004 | https://attack.mitre.org/techniques/T1078/004/ | yes | n/a | known gap | Baseline hides it; stolen pipeline SPs need sign-in-side rules (DAC-MDE-0113 / 0114). |
| Validate at subscription or management-group scope | T1580 | https://learn.microsoft.com/en-us/rest/api/resources/deployments/validate | yes | low | covered | Same operation name; Deployment ID differs but call counting still works. |

## FP check
New multi-template pipelines alert once, then fall into the baseline. Engineers looping validate while writing templates can alert. Volume not measured; no tenant data used.

## Unverified ideas
- Exact ActivityStatusValue values for validate (Started/Accepted/Succeeded/Failed assumed from the Learn column description).
- Whether CorrelationId is unique per validate call when issued from one CLI session (deployment ID counted as a fallback).
- Resource-type breadth from Properties_d (not verified, so not used).

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0122/ (synthetic, not run). Mirror 'now' is 2026-11-27T00:00Z.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_eleven_validations_in_8s | yes | alert | match |
| malicious_validations_across_resource_groups | yes | alert | match |
| malicious_same_name_new_correlations | yes | alert | match |
| benign_pipeline_known_burster | no | no alert | match |
| near_miss_four_validations | no | no alert | match |
| near_miss_status_rows_one_call | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Counting rows double-counts started and finished status rows | one call with 6 status rows | Count distinct CorrelationId / deployment ID |
| 2 | Grouping by caller and IP splits an agent that rotates egress IPs | same SP, two IPs | Group by Caller only; IPs listed |
| 3 | Pipelines that validate many stacks alert every run | known pipeline SP | 14-day per-caller burst baseline |
| 4 | Reused deployment name hides calls if only deployment IDs are counted | 5 calls, one name | max of correlation and deployment counts |
| 5 | Case of OperationNameValue varies (upper-case values are common in AzureActivity) | MICROSOFT.RESOURCES/DEPLOYMENTS/VALIDATE/ACTION | `=~` |

## Reviewer status
- pending human approval
