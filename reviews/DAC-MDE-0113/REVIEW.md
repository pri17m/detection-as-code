# REVIEW - DAC-MDE-0113 Entra: SP invalid or expired secret, then success

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). Microsoft describes the behaviour in prose; ThreatDefence Hunt 18 is an example hunt grouped by IP. This rule is written separately: it is keyed on AppId, enforces failure-before-success ordering inside a window, and uses a per-app source novelty test. No query text was copied.
- Microsoft 5 Nov 2026 post ('Sign-in errors AADSTS7000215 (invalid secret) or AADSTS7000222 (expired secret) indicate someone holds a credential for your app; a failure followed by a success is urgent'): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- ThreatDefence Hunt 18: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- AADServicePrincipalSignInLogs schema (AppId, ServicePrincipalId, ServicePrincipalName, ResultType, IPAddress, UserAgent, ResourceDisplayName): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs
- Entra error codes (AADSTS7000215 'Invalid client secret is provided'; AADSTS7000222 InvalidClientSecretExpiredKeysProvided; AADSTS7000218 missing client_assertion or client_secret): https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- ATT&CK v19.2: T1078.004 Cloud Accounts (initial-access); T1552.001 Credentials In Files (credential-access; the leaked secret came from public code).

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). Microsoft row M5 and ThreatDefence H18 were Gaps. Nothing on main referenced 7000215 or 7000222. DAC-ENTRA-0028 claims SP sign-in spikes but does not use the SP sign-in table.

## After
New defender (Sentinel KQL) rule DAC-MDE-0113 on AADServicePrincipalSignInLogs. The Microsoft post's own example queries use EntraIdSpnSignInEvents (Defender XDR); that table's error-code column naming was not checked field by field on this pass, so this rule targets the Sentinel table only.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Attacker has a working secret first time (no failure) | T1078.004 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | n/a | out of scope | Covered by the multi-SP (DAC-MDE-0114) and multi-resource (DAC-MDE-0115) rules. |
| Certificate or federated credential instead of a secret | T1078.004 | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs | partly | unknown | not added | Certificate failures use other AADSTS codes, not confirmed on this pass. |
| Fail from one IP, succeed from another | T1078.004 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | low | covered | Join is on AppId, not IP. |
| Wait over an hour between failure and success | T1078.004 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | medium | known gap | A wider window raises rotation noise; Microsoft's 5-minute GitHub-to-Key-Vault case fits 60 minutes. |
| Succeed from a source already used by the real app (for example same cloud egress) with fewer than 3 failures | T1078.004 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | n/a | known gap | Novelty test misses it by design. |

## Unverified ideas
- EntraIdSpnSignInEvents (Defender XDR) port: Microsoft's sample projects ErrorCode, ApplicationId, ServicePrincipalId, IPAddress. Field types not verified.
- Certificate-credential failure codes.
- Whether ResultType is always a string in this table (the query uses tostring()).

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0113/ (synthetic, not run). `_phase` marks baseline vs recent rows for the Python mirror.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_invalid_secret_then_success_new_source | yes | alert | match |
| malicious_many_failures_from_known_source | yes | alert | match |
| benign_rotation_expired_then_new_secret_known_host | no | no alert | match |
| near_miss_failure_without_success | no | no alert | match |
| near_miss_success_two_hours_later | no | no alert | match |
| near_miss_other_error_code | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Comparing min(fail) and min(success) per app (the report's draft sketch) misses a success that came before the failure and a later one after it | success 05:00, failure 06:00, success 06:02 | Join every success row and keep those inside FirstFail .. FirstFail+1h |
| 2 | Joining on two columns in a leftouter (AppId and IP) renames right-side columns and is easy to get wrong | AppId1 / IPAddress1 confusion | Single SourceKey string |
| 3 | `isempty()` on a bool from a non-matching leftouter row | KnownSource null | `isnull(KnownSource)` |
| 4 | Secret rotation on the app's own host fires every time | 7000222 once, then success from the usual IP | Novelty or 3+ failures required |
| 5 | AADSTS7000218 is a malformed request, not a wrong secret | 7000218 then success | Only 7000215 / 7000222 |
| 6 | Grouping by dynamic set columns is not allowed, and `distinct` takes column names, not expressions | `by FailCodes` (dynamic); `distinct SourceKey = strcat(...)` | `take_any()` for the sets; `extend` then `distinct` |

## Reviewer status
- pending human approval
