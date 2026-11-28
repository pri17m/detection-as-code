# REVIEW - DAC-MDE-0124 Sentinel: 3+ user-agent tool families from one source in a minute

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). Elastic's ES|QL hunt and ThreatDefence Hunt 17 are the starting shape (families per source per minute, 3+ families, 20+ requests). Differences: no ARTEX-named family (norma/artex strings are indicators, not families), IIS '+' encoding handled, unclassified agents not counted as a family, and a shared-egress baseline instead of excluding private address ranges. No query text was copied.
- Elastic Security Labs, Inside the loop ('one source address can use curl, a Python client, a browser User-Agent, and an AWS client within the same minute'; their example match is a developer workstation): https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex
- ThreatDefence Hunt 17 (three or more families and 20+ requests from one source in a minute): https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (ARTEX context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- W3CIISLog schema (cIP, csUserAgent, Computer, sSiteName, csUriStem, scStatus): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/w3ciislog
- CommonSecurityLog schema (SourceIP, RequestClientApplication 'The user agent associated with the request', RequestURL, DeviceVendor, DeviceProduct): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog
- IIS log collection to W3CIISLog: https://learn.microsoft.com/en-us/azure/azure-monitor/agents/data-collection-iis
- ATT&CK v19.2: T1595.002 Vulnerability Scanning, T1595.003 Wordlist Scanning (reconnaissance): https://attack.mitre.org/techniques/T1595/002/ https://attack.mitre.org/techniques/T1595/003/

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence H17 was a Gap; the report said W3CIISLog columns were unverified. They are now checked on Learn (links above).

## After
New defender (Sentinel KQL) rule DAC-MDE-0124. Families: aws-sdk, python, curl, go, scanner, browser. Alert when one source has 3+ classified families and 20+ requests in a minute, and is not a shared-egress source (same mix on 2+ days in the prior 14).

## UA gate (literal-match check)
No `where` clause tests a user-agent string. Strings only feed the Family() classifier; the alert condition is a count of families plus a request count. Removing any one family pattern cannot create an alert on its own.

## Noise gate
Kept, not dropped: the 2-day shared-egress baseline removes NAT, proxy and CDN addresses that mix tools daily, and unclassified agents never count, so browser-plus-one-script-plus-monitor traffic stays at 2 families. A one-off developer test still alerts (Elastic's own example); severity is medium for that reason. If the first week of results is dominated by developer ranges, raise MinRequests or drop the rule.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Spoof one browser UA for every tool | T1595.002 | https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting | yes | n/a | known gap | One family. ThreatDefence notes ReversingLabs saw stock Firefox defaults. |
| Spread workers across several source addresses | T1595.002 | https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex | yes | n/a | known gap | Grouping is per source. |
| Fewer than 20 requests per minute | T1595.003 | https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex | yes | lower | known gap | Threshold from Elastic. |
| Requests through a CDN that logs its own address as the client | T1595.002 | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/w3ciislog | partly | high | known gap | Needs X-Forwarded-For; such sources burst daily and sit in the baseline. |
| Tool families not in the classifier (Java, .NET HttpClient, Node fetch) | T1595.002 | https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex | yes | unknown | known gap | Unclassified UAs do not count; add families after measuring. |

## FP check
Developer and QA traffic, authorised scans, and unproxied CDN or WAF addresses are the expected benign sources. The baseline handles recurring ones. Volume not measured; no tenant data used.

## Unverified ideas
- Whether CommonSecurityLog RequestClientApplication is populated by the WAF/proxy vendors in use (varies by CEF source).
- Azure SDK and Azure CLI families (azsdk-*, AZURECLI) - not in the cited sources, left out.
- AppServiceHTTPLogs (UserAgent, CIp) as a third source for App Service fronted apps; columns not checked on this pass.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0124/ (synthetic, not run). Fixtures use W3CIISLog columns; the CommonSecurityLog branch is the same logic after projection. Mirror 'now' is 2026-11-27T00:00Z.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_browser_python_curl_aws_one_minute | yes | alert | match |
| malicious_python_curl_go_no_browser | yes | alert | match |
| malicious_iis_plus_encoded_agents | yes | alert | match |
| benign_shared_egress_daily | no | no alert | match |
| near_miss_two_families_many_requests | no | no alert | match |
| near_miss_three_families_few_requests | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | IIS writes spaces as '+', so 'mozilla/5.0 (' style patterns break | Mozilla/5.0+(X11;...) | Replace '+' before classifying; startswith patterns only |
| 2 | A 'norma' or 'artex' family is a disguised IOC match | norma/0.4 | Not a family |
| 3 | Excluding private ranges (Elastic, Hunt 17) is IP filtering and hides internal attackers | 10.x source | No range filter; shared-egress baseline instead |
| 4 | Browser + one script + 'other' counted as 3 families | Mozilla + python + SyntheticMonitor | Unclassified agents return an empty family and are not counted |
| 5 | Busy NAT addresses alert daily | office NAT | 2-day baseline |

## Reviewer status
- pending human approval
