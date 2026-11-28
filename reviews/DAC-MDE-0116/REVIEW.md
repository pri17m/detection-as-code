# REVIEW - DAC-MDE-0116 Azure Key Vault: list secrets then bulk read (data plane)

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence Hunt 7 (bulk Key Vault secret reads) and the Microsoft post describe the behaviour; this rule is written separately around the list-then-read shape with a first-seen caller baseline. No query text was copied.
- Microsoft 5 Nov 2026 post (agents 'exfiltrated secrets from the organization's Azure Key Vault'; GitHub to Key Vault exfil in five minutes; batch requests enumerating secret metadata across multiple vaults; 'Rotate everything stored in any Key Vault the affected application could read'): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- ThreatDefence Hunt 7: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- AZKVAuditLogs schema (OperationName, Identity, HttpStatusCode, Id 'Key ID or secret ID', CallerIpAddress, ClientInfo, _ResourceId, ResultSignature): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azkvauditlogs
- Key Vault logging (operation names SecretGet, SecretList, SecretListVersions; identity claim keys objectidentifier, upn, appid; Secret<action> naming): https://learn.microsoft.com/en-us/azure/key-vault/general/logging
- ATT&CK v19.2: T1555.006 Cloud Secrets Management Stores (credential-access).

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). Microsoft row M14 and ThreatDefence H7 were Partial through DAC-AZ-0014, which searches the Azure Activity log for SecretGet / SecretList names. Those are data-plane operation names recorded in Key Vault diagnostic logs, not reliably in the Activity log, and AZ-0014 has no volume or novelty logic. DAC-AZ-0039 repeats the same query.

## After
New defender (Sentinel KQL) rule DAC-MDE-0116 on AZKVAuditLogs. DAC-AZ-0014 is not edited in this PR (one rule per PR). Suggested follow-up: a separate PR that tags DAC-AZ-0014 and DAC-AZ-0039 `needs-review` and points to DAC-MDE-0116. Not done without approval.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Read secrets by guessed or known names without listing | T1555.006 | https://learn.microsoft.com/en-us/azure/key-vault/general/logging | yes | high | known gap | Name-only reads look like normal app behaviour. Volume-only alerting on SecretGet was dropped as high noise. |
| Use ARM (control plane) to read secret metadata instead of the data plane | T1555.006 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | partly | unknown | not added | Microsoft saw ARM requests for secret metadata. Key Vault logs do record ARM-originated vault calls (sample clientInfo azure-resource-manager), but the operation names for ARM secret reads were not confirmed on this pass. |
| Throttle reads to stay under 5 secrets per 10 minutes | T1555.006 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | n/a | known gap | Threshold trade-off; Microsoft's case was fast. |
| Use a caller that already lists secrets routinely | T1555.006 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | n/a | known gap | Baseline excludes it by design. |
| Vaults logging only to AzureDiagnostics (legacy mode) | T1555.006 | https://learn.microsoft.com/en-us/azure/key-vault/general/logging | yes, different table | n/a | not covered | A port to AzureDiagnostics column names is needed; those names were not verified on this pass. |

## Unverified ideas
- AzureDiagnostics (legacy) column names for the same fields.
- That the AZKVAuditLogs Identity column keeps the same nested claim keys as the raw diagnostic JSON on the logging page. The query falls back to tostring(Identity) when no claim matches.
- HttpStatusCode type (int vs string); the query uses toint().

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0116/ (synthetic, not run). `_phase` marks baseline vs recent rows for the Python mirror.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_list_then_get_eight_secrets | yes | alert | match |
| malicious_list_across_four_vaults | yes | alert | match |
| benign_app_reads_own_secrets_by_name | no | no alert | match |
| benign_daily_sync_tool | no | no alert | match |
| near_miss_list_then_four_reads | no | no alert | match |
| near_miss_list_then_denied_gets | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Activity-log search (AZ-0014) never sees data-plane SecretGet | SecretGet in AZKVAuditLogs only | Use AZKVAuditLogs |
| 2 | Counting SecretGet calls fires on an app reading its own two secrets in a loop | 30 gets of 2 names | Require a list, and count distinct vault/secret pairs |
| 3 | Denied reads are not exfiltration | 10 x 403 | `Status == 200` for SecretsRead |
| 4 | Secret names repeat across vaults | secret-1 in two vaults | Distinct on `Vault/SecretName` |
| 5 | Secret ID carries a version segment | /secrets/name/0123abcd | Regex takes only the name segment |
| 6 | Same filter written twice for baseline and live | drift on edit | One `KvSecretOps` function |

## Reviewer status
- pending human approval
