# REVIEW - DAC-AWS-0071 One principal denied across four or more AWS services in 15 minutes

## Attribution
Clean-room behavioural rule from Datadog Security Labs, "On the hunt for ARTEX: understanding agentic attacks in AWS environments" (Julie Agnes Sparks, 9 Nov 2026): https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/. Datadog published no query text; the SPL is our own, written from the article's described events and the AWS CloudTrail docs. No employer, client or tenant data. Fixtures are synthetic.

## As-is (new)
New rule. Nothing on `main` (bb44f2ab) counts AccessDenied across services per principal. DAC-AWS-0042 (ListBuckets) and DAC-AWS-0019/0020 (ListSecrets above a count) each see one service only.

## After
One actor with AccessDenied / AccessDeniedException / UnauthorizedOperation from 4+ eventSources and 8+ calls in one 15-minute bin. API-list free, so a different model picking different calls still fires.

Thresholds are unmeasured starting points, not tuned on real data. `telemetry_validated: false`.

## ATT&CK v19.2
T1526, T1580 -> discovery. Checked against enterprise-attack-19.2.json from mitre-attack/attack-stix-data (attack-pattern present, not revoked or deprecated; tactics from kill_chain_phases).

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Sweep split across a 15-minute bin edge (e.g. 4 denials at 11:14, 5 at 11:16) | MISSED if neither bin reaches 4 services and 8 calls. `bin` aligns to fixed clock edges | https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Bin |
| Slow sweep, one call every few minutes | MISSED: under the threshold in any one bin | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Calls that fail with a different error code (e.g. SNS `AuthorizationError`) | Not counted; the code list is the four in the query. SNS code unverified | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Attacker only calls APIs the role allows | MISSED here by design; DAC-AWS-0072 covers successful discovery | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |

## Unverified ideas
- The exact `errorCode` each service writes for a denied read (S3 `AccessDenied`, most JSON APIs `AccessDeniedException`, EC2 `Client.UnauthorizedOperation`). SNS and API Gateway values weren't checked against real events.
- Thresholds (4 services, 8 denials, 15 minutes) are unmeasured.
- The rule has no baseline. Datadog's own rule for this is anomaly-based.

## Tests / fixtures
`tests/cases/DAC-AWS-0071/`: all files are synthetic (`"synthetic": true`), built from the behaviour in the Datadog article and the CloudTrail record format. Account IDs are AWS example values and IPs are RFC 5737 documentation ranges; none are indicators. Not run by CI (the repo has no Splunk runner).

Splunk Enterprise 9.4.1 (local tarball on the agent box, throwaway instance). Splunk Add-on for AWS not installed, so `aws:cloudtrail` used `KV_MODE = json` with `TIME_FORMAT = %Y-%m-%dT%H:%M:%S%Z` in a local props.conf; field names are the raw CloudTrail JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -sourcetype aws:cloudtrail -index dac`, and the rule query ran unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). The events are synthetic, so this proves the SPL parses and the logic does what the fixture says. It says nothing about real tenant volume.

| Fixture | Label | Expect alert | Rows | Result | Rows with the draft SPL | What it is |
|---|---|---|---|---|---|---|
| benign_3_synthetic.json | benign | False | 0 | PASS | 0 | Same 9 discovery calls from an inventory role, all succeeded (no errorCode) |
| malicious_0_synthetic.json | malicious | True | 1 | PASS | 1 | Cognito-vended session denied on 9 discovery calls across 8 services in 3 minutes (Datadog's list) |
| near_miss_1_synthetic.json | near_miss | False | 0 | PASS | 0 | 8 denials but only 3 services (S3, Secrets Manager, SSM) |
| near_miss_2_synthetic.json | near_miss | False | 0 | PASS | 0 | 5 services denied but only 5 calls |

## Ponytail findings
Ponytail pass (2026-11-12): correctness, safety, behaviour under load, tests, speed, every line needed. Findings naming a fixture were replayed in local Splunk against the pre-fix draft SPL (our research notes, before this PR); the rest are reasoned.

- F1 (triage): failing input: `malicious_0_synthetic.json`: the draft SPL returned 1 row with no source address or user agent, so the analyst couldn't tell an agent from a broken pipeline without a second search. Fix: Added `values(sourceIPAddress) AS src_ip values(userAgent) AS user_agent` and `sort - services`. Same 1 row, with context.
- F2 (null keys): failing input: Reasoned: the draft grouped `BY userIdentity.type`; an event without it drops out of `stats`. Fix: `id_type=coalesce('userIdentity.type',"unknown")`; `actor` falls back to "unknown".
- F3 (window edge, not fixed): failing input: Reasoned: a 9-call sweep straddling a 15-minute edge splits into two bins below threshold. Fix: No change in this PR: a sliding window (`streamstats time_window=15m`) changes cost and semantics and needs real data to tune. Listed in the bypass table.

## Reviewer status
pending human review (merge approved by the repo owner in chat, 2026-11-12)
