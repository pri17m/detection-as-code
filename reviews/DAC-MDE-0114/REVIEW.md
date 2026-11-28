# REVIEW - DAC-MDE-0114 Entra: one source signs in as 3+ service principals with mixed results

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). Microsoft states the behaviour in prose; ThreatDefence Hunt 18 (IP group, 3+ SPs) and Hunt 19 (30-day first-seen baseline) are example hunts. This rule combines the mixed-result test with a per source+app first-seen baseline and was written separately; no query text was copied.
- Microsoft 5 Nov 2026 post ('Look for behavior as well as the IP: one address authenticating to three or more service principals with mixed success'; agent signed in as dozens of apps across tenants): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- ThreatDefence Hunts 18 and 19: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- AADServicePrincipalSignInLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs
- Entra error codes (7000215, 7000222): https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- KQL make_set_if: https://learn.microsoft.com/en-us/kusto/query/make-set-if-aggregation-function
- ATT&CK v19.2: T1078.004 Cloud Accounts.

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). Microsoft row M4 and ThreatDefence H19 (multi-SP part) were Gaps. Nothing on main counted distinct service principals per source.

## After
New defender (Sentinel KQL) rule DAC-MDE-0114. Group key is IPAddress per Microsoft's wording. Novelty is per (IP, AppId) pair over 14 days.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Use a different IP per app (Tor exits, rotating proxies) | T1078.004 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | high | known gap | Grouping by UserAgent instead was considered; common SDK user agents (azure-identity, MSAL) are shared by many legit workloads, so UA-only grouping is high noise. Listed for tuning. |
| Only valid secrets, so no failures | T1078.004 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | medium | known gap | Mixed results are Microsoft's stated signal; an all-success variant would hit every multi-app integration host. DAC-MDE-0115 covers the token spread of one app. |
| Spread sign-ins over more than an hour | T1078.004 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | n/a | known gap | Window trade-off. |
| Reuse an address the victim's own workloads use | T1078.004 | https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/ | yes | n/a | known gap | Baseline suppresses it by design. |

## Unverified ideas
- UserAgent as a secondary group key after measuring noise.
- EntraIdSpnSignInEvents port (Defender XDR table named in Microsoft's queries); columns not verified field by field.
- Cross-tenant view (MSSP) where the same address hits several tenants.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0114/ (synthetic, not run). `_phase` marks baseline vs recent rows for the Python mirror.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_five_apps_mixed_from_one_source | yes | alert | match |
| malicious_three_apps_with_expired_secret | yes | alert | match |
| benign_known_ci_runner_with_one_expired_app | no | no alert | match |
| near_miss_all_successes | no | no alert | match |
| near_miss_two_apps_only | no | no alert | match |
| near_miss_all_failures | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | A plain 3+ SP count fires on every integration host | CI runner with 4 apps, all OK daily | Mixed success and failure, plus 2+ pairs new in 14 days |
| 2 | Counting failures, not failed apps, lets one app's retry storm satisfy 'mixed' | one app failing 20 times plus two OK apps | `dcountif(AppId, not(Ok))` |
| 3 | Empty IPAddress rows (some Microsoft-internal flows) would form one giant group | blank IP across many apps | `isnotempty(IPAddress)` |
| 4 | Non-matching leftouter rows give a null bool | KnownPair null | `isnull(KnownPair)` |

## Reviewer status
- pending human approval
