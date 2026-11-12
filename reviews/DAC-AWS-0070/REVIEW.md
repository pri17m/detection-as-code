# REVIEW - DAC-AWS-0070 CloudWatch Logs FilterLogEvents searched for credentials or storage links

## Attribution
Clean-room behavioural rule from Datadog Security Labs, "On the hunt for ARTEX: understanding agentic attacks in AWS environments" (Julie Agnes Sparks, 9 Nov 2026): https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/. Datadog published no query text; the SPL is our own, written from the article's described events and the AWS CloudTrail docs. No employer, client or tenant data. Fixtures are synthetic.

## As-is (new)
New rule. Nothing on `main` (bb44f2ab, 69 DAC-AWS rules) looks at CloudWatch Logs `FilterLogEvents`. Our coverage check of the article found no rule for this behaviour.

## After
`FilterLogEvents` calls whose `filterPattern` hunts for AKIA, password, presigned, s3://, .csv or .xlsx, grouped per actor and access key. Alerts on any AKIA or password search, or on 3+ searches where at least one is secret-like. Calls with `limit=1000` from an `AKIA` key are kept and counted (`akia_limit_1000_calls`) but never alert on their own.

Thresholds are unmeasured starting points, not tuned on real data. `telemetry_validated: false`.

## ATT&CK v19.2
T1552, T1526 -> credential-access, discovery. Checked against enterprise-attack-19.2.json from mitre-attack/attack-stix-data (attack-pattern present, not revoked or deprecated; tactics from kill_chain_phases).

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Only financial-term searches (company name + Fund/Invoice/LLC), like the first session Datadog describes | MISSED by design. Those terms are tenant-specific; the limit=1000 + AKIA context is counted but does not alert (F1) | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Search with a temporary ASIA key instead of AKIA | Still alerts on the filter terms; `long_term_key` is 0 so triage loses that signal | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html |
| CloudWatch Logs Insights (`StartQuery`) instead of FilterLogEvents | MISSED: different API; query text field not checked here | https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/logging_cw_api_calls_cwl.html |
| Obfuscated term, e.g. `?AK?A` wildcards or split terms | MISSED: regex looks for literal substrings | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Two searches only, neither for AKIA/password | MISSED: below the 3-search threshold (unmeasured) | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |

## Unverified ideas
- Whether CloudTrail records `requestParameters.filterPattern` and `requestParameters.limit` for FilterLogEvents verbatim. Datadog quotes the search terms and the limit, which suggests it does, but no AWS sample event for FilterLogEvents was found.
- Whether FilterLogEvents is logged as a management or data event in current CloudTrail (the AWS page lists it as logged but doesn't say which). If it's a data event, a default trail won't have it.
- Thresholds (3 searches, the term list) are unmeasured. No benign volume data.

## Tests / fixtures
`tests/cases/DAC-AWS-0070/`: all files are synthetic (`"synthetic": true`), built from the behaviour in the Datadog article and the CloudTrail record format. Account IDs are AWS example values and IPs are RFC 5737 documentation ranges; none are indicators. Not run by CI (the repo has no Splunk runner).

Splunk Enterprise 9.4.1 (local tarball on the agent box, throwaway instance). Splunk Add-on for AWS not installed, so `aws:cloudtrail` used `KV_MODE = json` with `TIME_FORMAT = %Y-%m-%dT%H:%M:%S%Z` in a local props.conf; field names are the raw CloudTrail JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -sourcetype aws:cloudtrail -index dac`, and the rule query ran unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). The events are synthetic, so this proves the SPL parses and the logic does what the fixture says. It says nothing about real tenant volume.

| Fixture | Label | Expect alert | Rows | Result | Rows with the draft SPL | What it is |
|---|---|---|---|---|---|---|
| benign_3_synthetic.json | benign | False | 0 | PASS | 0 | One presigned-URL troubleshooting search by an SSO role (no AKIA/password, single call) |
| malicious_0_synthetic.json | malicious | True | 1 | PASS | 1 | One FilterLogEvents call with Datadog's quoted database/secret pattern from a long-term key |
| malicious_1_synthetic.json | malicious | True | 1 | PASS | 1 | Three storage-link searches with limit=1000 across log groups, no password/AKIA term |
| near_miss_2_synthetic.json | near_miss | False | 0 | PASS | 1 | Three limit=1000 searches from an AKIA key for ordinary error strings (weak branch only) |

## Ponytail findings
Ponytail pass (2026-11-12): correctness, safety, behaviour under load, tests, speed, every line needed. Findings naming a fixture were replayed in local Splunk against the pre-fix draft SPL (our research notes, before this PR); the rest are reasoned.

- F1 (fidelity): failing input: `near_miss_2_synthetic.json`: three `limit=1000` searches from an AKIA key for `?Error ?Exception`, `?timeout`, `?Error`. The draft SPL alerted (1 row) because `count>=3` counted the weak limit=1000 branch on its own, which contradicts its own false-positive note. Fix: Final filter is `cred_search=1 OR (count>=3 AND secret_searches>=1)`. Replay: 0 rows.
- F2 (null keys): failing input: Reasoned: the the draft grouped `BY userIdentity.accessKeyId`; a FilterLogEvents event without `accessKeyId` would drop out of `stats`. Fix: `key_id`, `id_type` and `actor` are coalesced to a value before `stats`.
- F3 (field name): failing input: Reasoned: FilterLogEvents accepts `logGroupIdentifier` as well as `logGroupName` (API reference); the draft counted only `logGroupName`. Fix: `log_group=coalesce('requestParameters.logGroupName','requestParameters.logGroupIdentifier',"unknown")`.

## Reviewer status
pending human review (merge approved by the repo owner in chat, 2026-11-12)
