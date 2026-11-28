# REVIEW - DAC-MDE-0110 Entra: an application changes its own access

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence published an example hunt (Hunt 5) that lists app-initiated changes and flags self-changes as a column; this rule is written separately, adds role-eligibility and owner cases, matches the actor anywhere in the targets (including modifiedProperties), and alerts only on self-changes. No query text was copied.
- ThreatDefence Hunt 5 (Storm-0940 agents added credentials to applications; one application assigned itself Global Administrator): https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (remove credentials 'including those added by the threat actor'): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- AuditLogs table schema (InitiatedBy, TargetResources, OperationName, Result): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
- Entra audit activity names (Add service principal credentials, Add member to role, Add eligible member to role, Add app role assignment to service principal, Add owner to service principal, Add owner to application, Update application - Certificates and secrets management): https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Graph appIdentity (appId, displayName, servicePrincipalId, servicePrincipalName): https://learn.microsoft.com/en-us/graph/api/resources/appidentity
- Graph targetResource (id, displayName, type, modifiedProperties): https://learn.microsoft.com/en-us/graph/api/resources/targetresource
- Graph addKey (apps can roll their own keys without extra permission; FP source): https://learn.microsoft.com/en-us/graph/api/application-addkey
- Entra security operations guide for applications (credential and role-assignment monitoring): https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications
- KQL string operators (has works on whole terms; GUIDs split into several terms, so contains is used): https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators
- ATT&CK v19.2: T1098.001 Additional Cloud Credentials, T1098.003 Additional Cloud Roles (tactics persistence, privilege-escalation).

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence Hunt 5 and Microsoft row M21 were Partial:
- DAC-ENTRA-0005 / DAC-ENTRA-0006: credential add on a (privileged) app by any actor. No InitiatedBy.app requirement, no self test.
- DAC-ENTRA-0001 / DAC-MDE-0082: privileged role assignment, any actor.
- DAC-ENTRA-0004: title says self-elevation but compares user UPN fields, so an application assigning itself a role is missed.
None of these is changed here.

## After
New defender (Sentinel KQL) rule DAC-MDE-0110: InitiatedBy.app.servicePrincipalId present, operation in the credential / role / eligible role / app-role / owner set, and the actor's SP object ID or appId found in the lower-cased TargetResources text. ChangeKind column says which. Credential adds can be allowlisted per AppId.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| App A grants App B, then B grants A (two compromised apps cross-granting) | T1098.003 | https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting | yes | medium | known gap | Not a self-change. Would need a correlation of app-initiated grants between two apps within a window; left as an idea. |
| Credential added to the application object instead of the service principal | T1098.001 | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities | partly | low | covered if appId is in targets | 'Update application - Certificates and secrets management' targets the application object; whether appId appears in TargetResources is unverified (see Unverified). |
| Federated identity credential added instead of a secret or cert | T1098.001 | https://learn.microsoft.com/en-us/graph/api/resources/appidentity | unverified | unknown | not added | The exact audit OperationName for federated credential adds was not confirmed on the activity reference page on this pass. |
| Self role assignment through Azure RBAC (subscription Owner) rather than an Entra directory role | T1098.003 | https://attack.mitre.org/techniques/T1098/003/ | no (AzureActivity, not AuditLogs) | n/a | not detectable here | Different log source; DAC-AZ-0001/0003 cover role assignment without the self test. |
| PIM activation wording ('Add member to role in PIM completed') | T1098.003 | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities | yes | low | covered | `startswith "Add member to role"` also matches the PIM and Restricted Management AU variants listed on the activity page. |

## Unverified ideas
- Whether TargetResources for an application-object credential add carries the appId anywhere. If not, add a lookup from application object ID to appId.
- Exact OperationName for federated identity credential adds.
- Cross-app grant correlation (two apps granting each other in one hour).
- Pairing a self credential add with a later sign-in from a new source (overlaps DAC-MDE-0083).

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0110/, all `"synthetic": true`, result not run. Python mirror applied to fixtures (logic only).

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_app_assigns_itself_global_admin | yes | alert | match |
| malicious_app_grants_itself_graph_app_role | yes | alert | match |
| malicious_app_adds_own_secret | yes | alert | match |
| benign_admin_user_adds_secret | no | no alert | match |
| near_miss_app_grants_role_to_other_sp | no | no alert | match |
| near_miss_self_role_failed | no | no alert | match |

CI validate: see PR checks. Not run in a live Sentinel workspace.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Comparing only TargetResources[0].id misses app-role self grants, where target[0] is the resource API (Microsoft Graph) and the assignee is in modifiedProperties | Add app role assignment to service principal, target[0] = Microsoft Graph SP | Search the whole TargetResources text for the actor IDs |
| 2 | `has` on a GUID depends on term splitting (hyphens split terms) | `has "1111-2222-..."` | Use `contains` on lower-cased text |
| 3 | An empty actor appId with `contains ""` would match everything | InitiatedBy.app with no appId | `isnotempty(ActorAppId) and ...` guard |
| 4 | The credential activity name carries a long-dash variant and trailing text in real logs | 'Update application - Certificates and secrets management' with a different dash | `has "Certificates and secrets management"` instead of equality |
| 5 | Failed changes should not alert | Result = failure | `Result =~ "success"` |
| 6 | Legit self-rotation via addKey | app rolling its own certificate | KnownSelfRotatingAppIds allowlist for credential rows only; role and app-role self grants are never allowlisted |

## Reviewer status
- pending human approval
