# REVIEW - DAC-MDE-0123 Sentinel: first-seen Kudu or FTP publishing logon to an App Service app

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence Hunt 15 flags any logon from a UserAddress not used on that resource in a 90-to-7-day window; this rule uses identity novelty for every credential type and adds source novelty only for app-scope credentials on apps with stable deploy egress. No query text was copied.
- Google Threat Intelligence Group, ARTEX and Friends (Kudu credentials among those mapped; 'Abused Kudu administrative APIs to execute arbitrary commands and stage custom Python, C#, and malicious PowerShell scripts'; Kudu/SCM hardening advice): https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- ThreatDefence Hunt 15 (publishing sign-ins through Kudu or FTP from addresses not used before): https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (ARTEX context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- AppServiceAuditLogs schema (User 'Username used for publishing access', UserAddress, UserDisplayName 'Email address of a user in case publishing was authorized via AAD authentication', Protocol 'Authentication protocol', OperationName, _ResourceId) and table description: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceauditlogs
- App Service monitoring reference (AppServiceAuditLogs = 'Login activity via FTP and Kudu'): https://learn.microsoft.com/en-us/azure/app-service/monitor-app-service-reference
- Deployment credentials (app-scope user names `$app-name` and `app-name\$app-name`; basic auth off by default for new apps): https://learn.microsoft.com/en-us/azure/app-service/deploy-configure-credentials
- Kudu service overview (SCM site, run commands in the Kudu console): https://learn.microsoft.com/en-us/azure/app-service/resources-kudu
- ATT&CK v19.2 T1078.004 Valid Accounts: Cloud Accounts (initial access, persistence): https://attack.mitre.org/techniques/T1078/004/

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence H15c was a Gap. The report asked to verify the AppServiceAuditLogs fields: User, UserAddress, UserDisplayName and Protocol are on Learn; there is no SiteName column, so the app is _ResourceId. Only successful logons are logged.

## After
New defender (Sentinel KQL) rule DAC-MDE-0123. Established app (publishing logons in the prior 30 days); reason new-identity-on-site, or app-credential-from-new-source for app-scope users whose baseline came from 5 or fewer addresses.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Stolen app-scope credential used from the same egress as the pipeline (for example from a compromised runner) | T1078.004 | https://learn.microsoft.com/en-us/azure/app-service/deploy-configure-credentials | yes | n/a | known gap | Identity and source both known. |
| App-scope credential on an app that deploys from rotating hosted runners | T1078.004 | https://learn.microsoft.com/en-us/azure/app-service/deploy-configure-credentials | yes | high | known gap | Source novelty switched off for those apps to avoid daily alerts. |
| Failed publishing logons (password guessing) | T1110 | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceauditlogs | no | n/a | not loggable | Table records successful logons only. |
| Kudu via Entra ID with a stolen token instead of basic auth | T1550.001 | https://learn.microsoft.com/en-us/azure/app-service/resources-kudu | yes | medium | covered | UserDisplayName carries the Entra identity; new identity on the app alerts. |
| Use a brand-new app in the same subscription | T1078.004 | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceauditlogs | yes | n/a | known gap | New apps are excluded; their first logon has no baseline. |
| ARM-level publishing credential read (Web/sites/config/list/Action) before the logon | T1552 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | yes | low | out of scope | AzureActivity rule idea (report M11), not this table. |

## FP check
New engineers or pipelines on existing apps alert once. Self-hosted runner moves can alert in the source branch. Volume not measured; no tenant data used.

## Unverified ideas
- Protocol values (for example Basic, AAD, FTP) were not listed on Learn; the rule does not filter on them. Fixture values are placeholders.
- OperationName value for publishing logons (fixture uses 'Authorization', a placeholder).
- Whether UserDisplayName is empty or the same as User for basic-auth logons (coalesce handles both).
- AppServiceHTTPLogs / Kudu command API calls as a follow-on signal (T1651 Cloud Administration Command), not built.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0123/ (synthetic, not run). Mirror 'now' is 2026-11-27T00:00Z.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_stolen_publish_profile_new_source | yes | alert | match |
| malicious_new_user_scope_identity | yes | alert | match |
| malicious_new_aad_identity_kudu | yes | alert | match |
| benign_known_pipeline | no | no alert | match |
| benign_rotating_runner_site | no | no alert | match |
| near_miss_brand_new_site | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Address-only novelty (Hunt 15) fires on every hosted-runner deployment | 25 addresses in 25 days | Source branch only for apps with 5 or fewer addresses |
| 2 | Identity-only novelty misses a stolen publish profile, because the app credential is always the same user | $shop-api from a new address | App-scope source branch |
| 3 | Brand-new apps would alert on their first deployment | first logon to new-app | Established-site join |
| 4 | Basic-auth logons may not carry UserDisplayName | User only | coalesce(UserDisplayName, User) |
| 5 | Site-name column assumed by the report does not exist | SiteName | _ResourceId |

## Reviewer status
- pending human approval
