# REVIEW - DAC-MDE-0109 Entra: password spray with a fixed one-second rhythm

## Attribution
Clean-room behavioural rule written from public sources opened on 28 Nov 2026 (IST). ThreatDefence published an example hunt for the same idea; this query is written separately (different failure-code filter, two-step gap statistics, P75 steadiness test, success context) and no query text was copied.
- Wiz, ARTEX in the wild (spray bursts, strict one-second median gap, unique user agent per burst, 20-60 minute bursts, some users hit more than a dozen times): https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors
- ThreatDefence ARTEX detection and hunting, Hunt 2 and Hunt 3: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft, 5 Nov 2026 agentic secret abuse post (ARTEX context; spray is adjacent to that chain, not in it): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- SigninLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- AADNonInteractiveUserSignInLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs
- Entra error codes (AADSTS50126 InvalidUserNameOrPassword, AADSTS50053 IdsLocked or blocked source): https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- KQL prev() and percentile(): https://learn.microsoft.com/en-us/kusto/query/prev-function , https://learn.microsoft.com/en-us/kusto/query/percentiles-aggregation-function
- ATT&CK v19.2 (local STIX enterprise-attack-19.2.json): T1110.003 Password Spraying, tactic credential-access. https://attack.mitre.org/techniques/T1110/003/

No detections.ai content, no employer data, no CrowdStrike tenant data. Fixtures are synthetic.

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence Hunt 2 was scored Partial. On main at the time of writing:
- DAC-ENTRA-0033 (Splunk, azure:monitor:aad): many users fail from one IP in a 15-minute bin, attempts per user under 5. No timing test, SignInLogs only, and the attempts-per-user cap would miss Wiz's "more than a dozen attempts" users.
- DAC-ENTRA-0034: successes from one IP across 10+ users. No failure stage.
- DAC-OKTA-0011 does not cover spray rhythm.

## After
New defender (Sentinel KQL) rule DAC-MDE-0109. Unions interactive and non-interactive sign-ins, keeps 50126 and 50053, groups by IPAddress plus UserAgent per hour, and fires when 20+ users and 120+ attempts show a median gap of 2 s or less and a P75 gap of 3 s or less. Successes from the same pair are attached as context.

Okta: not built in this PR. The Okta System Log event user.session.start is documented, but there is no Okta Sentinel table schema or Splunk attack_data payload opened for this pass, so an Okta query would rest on unverified field names. Left as an open question.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Rotate IP mid-burst (Wiz: new addresses appeared within minutes when blocked) | T1110.003 | https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors | yes (IPAddress) | n/a | known gap | Each IP+UA pair is scored alone; a burst split across many IPs falls under the 120-attempt floor per pair. Grouping on UserAgent alone was considered and dropped: a common browser UA across a large tenant can show a short median gap by chance (high noise). |
| Rotate user agent per burst | T1110.003 | https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors | yes | low | covered | A new UA per burst is still one stable UA for the burst's duration, so the pair holds for the burst. |
| Slow the spray (one attempt every 30 s or more) | T1110.003 | https://attack.mitre.org/techniques/T1110/003/ | yes | n/a | known gap | Out of scope by design; DAC-ENTRA-0033 still covers volume-only spray. |
| Spray against a legacy or non-Entra endpoint (Okta, ADFS, app login pages) | T1110.003 | https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors | no (not in these tables) | n/a | not detectable here | Different log source. |
| Valid username list only (no 50034 unknown-user noise) | T1110.003 | https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes | yes | low | covered | 50126 is returned for wrong password on a real user. |
| Spray producing other failure codes (for example 50076 MFA required when the password is right) | T1110.003 | https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes | yes | high | dropped | 50076 and similar codes also come from normal MFA flows; adding them would raise noise. Successes and MFA prompts are listed as context only. |

## Unverified ideas
- Okta port (user.session.start failures with outcome.result FAILURE). Needs an opened schema for whichever Okta table or sourcetype is used.
- Whether percentile() ignores null values; the query avoids relying on it by filtering nulls before the gap summarize.
- Sub-second TimeGenerated precision in every workspace. If TimeGenerated is truncated to the second, many gaps become 0 or 1; the median test still holds, but this is unverified.
- Real-world false-positive volume for shared egress points. Not measured.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0109/, each marked `"synthetic": true` with a `result` that says not run. There is no KQL runner in this repo. The rule logic was mirrored in Python and applied to the fixtures; that checks logic, not KQL syntax.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_one_second_spray_40_users | yes | alert | match |
| malicious_spray_with_lockouts | yes | alert | match |
| benign_shared_proxy_many_users_irregular | no | no alert | match |
| near_miss_fast_brute_force_five_users | no | no alert | match |
| near_miss_mfa_required_not_password_failure | no | no alert | match |
| near_miss_below_attempt_threshold | no | no alert | match |

CI validate: see the PR checks. The query was not run in a live Sentinel workspace or in Splunk.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | percentile() over a column whose first row per group is null relies on undocumented null handling | first attempt of every IP+UA group has no previous row | Gap stats are computed in a separate summarize after `where isnotnull(GapSec)` |
| 2 | An attempts-per-user cap (as in DAC-ENTRA-0033) misses users who are hit a dozen times | 40 users, 180 attempts, 4.5 per user is fine, but 20 users with 13 attempts each fails a `<5` cap | No per-user cap; spray shape comes from 20+ distinct users |
| 3 | Grouping by IP alone mixes the spray with normal failures from the same NAT and breaks the rhythm | proxy IP with real users failing plus a spray behind the same IP | Group by IPAddress plus UserAgent (Wiz: one UA per burst) |
| 4 | Empty UserAgent would make the group key null and drop rows from the join | non-interactive sign-ins with empty UserAgent | `iff(isempty(UserAgent), "(empty)", UserAgent)` |
| 5 | Workspaces without AADNonInteractiveUserSignInLogs would fail the union | tenant without non-interactive logs connected | `union isfuzzy=true` |
| 6 | Median alone lets a spray hide inside long pauses, and lets a bursty human pattern through | 150 attempts, half at 1 s and half at 60 s | Added a P75 gap test of 3 s or less |
| 7 | ResultType type differs between tables (string vs number in some exports) | numeric 50126 | `tostring(ResultType)` before comparison |

## Reviewer status
- pending human approval
