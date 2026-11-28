# REVIEW - DAC-MDE-0115 Entra: one app gets tokens for ARM, Key Vault, Storage and Graph

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence Hunt 19 is an example that counts distinct ResourceDisplayName; this rule classes resources by application ID into the four classes Microsoft names (so other resources do not inflate the count) and was written separately. No query text was copied.
- Microsoft 5 Nov 2026 post ('one app requesting tokens across Azure Resource Manager, Key Vault, Storage and Graph in a short window'): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- ThreatDefence Hunt 19: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- AADServicePrincipalSignInLogs schema (ResourceIdentity 'ID of the resource that the service principal signed into', ResourceDisplayName): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs
- Resource application IDs, Microsoft Learn first-party list (Microsoft Graph 00000003-0000-0000-c000-000000000000; Windows Azure Service Management API 797f4846-ba00-4fd7-ba43-dac1f8f63013; Azure Key Vault cfa8b339-82a2-471a-a3c9-0fc0be7a4093; Azure Storage e406a681-f3d4-42a8-90b6-c2b029497af1): https://learn.microsoft.com/en-us/connectors/custom-connectors/auth-script
- KQL user-defined scalar functions: https://learn.microsoft.com/en-us/kusto/query/functions/user-defined-functions
- ATT&CK v19.2: T1526 Cloud Service Discovery (discovery); T1528 Steal Application Access Token (credential-access).

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). Microsoft row M6 and ThreatDefence H19 were Gaps. Nothing on main counted resource spread per app.

## After
New defender (Sentinel KQL) rule DAC-MDE-0115.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Touch only two of the four (for example ARM then Key Vault) | T1526 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | high | known gap | Two-class apps are very common (ARM + Graph). Lowering to 2 would be high noise. |
| Use Azure management via a different resource (Azure Service Management legacy endpoints, AKS, Log Analytics) | T1526 | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs | yes | unknown | not added | Only the four resources Microsoft names are classed, to keep the logic tied to the source. |
| Spread token requests over more than 15 minutes | T1526 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | medium | known gap | Microsoft's 5-minute GitHub-to-Key-Vault case fits the window. |
| Steal tokens rather than the secret (no sign-in row) | T1528 | https://attack.mitre.org/techniques/T1528/ | no | n/a | not detectable here | Token replay does not create a new SP sign-in. |

## Unverified ideas
- That ResourceIdentity holds the resource application ID (and not the resource service principal object ID) in every tenant. ResourceServicePrincipalId exists as a separate column, which suggests ResourceIdentity is the app ID, but this was not seen on a sample. Display names are a fallback for that reason.
- EntraIdSpnSignInEvents port.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0115/ (synthetic, not run). `_phase` marks baseline vs recent rows for the Python mirror.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_all_four_resources_in_six_minutes | yes | alert | match |
| malicious_three_resources_matched_by_display_name | yes | alert | match |
| benign_backup_tool_does_this_daily | no | no alert | match |
| near_miss_two_resources | no | no alert | match |
| near_miss_failed_key_vault_token | no | no alert | match |
| near_miss_spread_across_two_hours | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Counting any distinct resource lets SharePoint + Exchange + Graph satisfy '3 resources' with none of ARM / Key Vault / Storage | Graph, Office 365 Exchange Online, SharePoint | Class only the four named resources |
| 2 | Free-text display names can change or be localised | ResourceDisplayName 'Azure Resource Manager' vs 'Windows Azure Service Management API' | Match by application ID first, display name second |
| 3 | Baseline and live paths classing resources differently | edit one case() only | One scalar `ResourceClassOf` function used by both. A tabular function with a partial schema was dropped because the Learn page does not say whether extra input columns pass through |
| 4 | Failed token requests counted as reach | Key Vault 7000215 | `ResultType == "0"` |

## Reviewer status
- pending human approval
