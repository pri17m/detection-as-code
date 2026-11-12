# REVIEW - DAC-AWS-0074 Cognito user pool self sign-up followed by AWS discovery from the same source within 60 minutes

## Attribution
Clean-room behavioural rule from Datadog Security Labs, "On the hunt for ARTEX: understanding agentic attacks in AWS environments" (Julie Agnes Sparks, 9 Nov 2026): https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/. Datadog published no query text; the SPL is our own, written from the article's described events and the AWS CloudTrail docs. No employer, client or tenant data. Fixtures are synthetic.

## As-is (new)
New rule. Nothing on `main` (bb44f2ab) looks at Cognito user pool `SignUp` events or ties them to later AWS API calls.

## After
Cognito `SignUp` (API, Hosted UI `Signup_POST`, managed login `signup_POST`), then at least one discovery call from the same `sourceIPAddress` within 60 minutes after the latest sign-up. `streamstats` carries the last sign-up time per source, so the order and gap are checked per event. Failed sign-ups, auth calls and a `CognitoIdentityCredentials` session name are reported as supporting evidence.

Thresholds are unmeasured starting points, not tuned on real data. `telemetry_validated: false`.

## ATT&CK v19.2
T1136.003, T1078.004, T1526 -> persistence, initial-access, discovery. Checked against enterprise-attack-19.2.json from mitre-attack/attack-stix-data (attack-pattern present, not revoked or deprecated; tactics from kill_chain_phases).

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Discovery from a different egress IP than the sign-up (proxy rotation) | MISSED: the join key is the source address | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Discovery more than 60 minutes after sign-up | MISSED (near_miss_1) | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Sign-up outside the search window, discovery inside it | MISSED: schedule lookback must be at least 60 minutes | https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Streamstats |
| Attacker only abuses ForgotPassword / ResendConfirmationCode (Wiz pattern) | MISSED: no SignUp | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Discovery via services outside the 9 listed APIs | MISSED | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |

## Unverified ideas
- Correlation assumption 1: the user pool `SignUp` event and the later `CognitoIdentityCredentials` API calls carry the same client `sourceIPAddress`. Datadog's write-up implies one source; not checked against real events.
- Correlation assumption 2: the session name `CognitoIdentityCredentials` comes from Datadog's write-up; AWS docs don't list it as a constant, so it is only reported (`cognito_session`), not required.
- The identity-pool exchange (`GetId`, `GetCredentialsForIdentity`) is a CloudTrail data event (off by default) per the Cognito logging page, so it isn't used as a stage.
- `userIdentity` shape for unauthenticated user pool calls (`type` Unknown / `principalId` Anonymous) in the fixtures is synthetic.
- Shared NAT or corporate egress can join unrelated sign-ups and API calls; volume not measured. The 60-minute window is unmeasured.

## Tests / fixtures
`tests/cases/DAC-AWS-0074/`: all files are synthetic (`"synthetic": true`), built from the behaviour in the Datadog article and the CloudTrail record format. Account IDs are AWS example values and IPs are RFC 5737 documentation ranges; none are indicators. Not run by CI (the repo has no Splunk runner).

Splunk Enterprise 9.4.1 (local tarball on the agent box, throwaway instance). Splunk Add-on for AWS not installed, so `aws:cloudtrail` used `KV_MODE = json` with `TIME_FORMAT = %Y-%m-%dT%H:%M:%S%Z` in a local props.conf; field names are the raw CloudTrail JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -sourcetype aws:cloudtrail -index dac`, and the rule query ran unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). The events are synthetic, so this proves the SPL parses and the logic does what the fixture says. It says nothing about real tenant volume.

| Fixture | Label | Expect alert | Rows | Result | Rows with the draft SPL | What it is |
|---|---|---|---|---|---|---|
| benign_3_synthetic.json | benign | False | 0 | PASS | 0 | A real user signs up and authenticates; no AWS discovery calls follow |
| malicious_0_synthetic.json | malicious | True | 1 | PASS | 1 | 3 failed SignUps, 1 success, user pool auth flow, then denied discovery sweep under CognitoIdentityCredentials 15 minutes later, same source |
| malicious_4_synthetic.json | malicious | True | 1 | PASS | 0 | Sign-up chain from 10:50Z, discovery sweep at 11:05Z: 15 minutes apart, on either side of the 11:00Z 60-minute bin edge |
| near_miss_1_synthetic.json | near_miss | False | 0 | PASS | 0 | Same sign-up chain, but the discovery sweep comes 2 hours later |
| near_miss_2_synthetic.json | near_miss | False | 0 | PASS | 0 | Discovery sweep 10 minutes before the sign-up, nothing after |
| near_miss_5_synthetic.json | near_miss | False | 0 | PASS | 1 | Discovery at 10:05, sign-up chain at 10:20 in the same clock hour; discovery came first |

## Ponytail findings
Ponytail pass (2026-11-12): correctness, safety, behaviour under load, tests, speed, every line needed. Findings naming a fixture were replayed in local Splunk against the pre-fix draft SPL (our research notes, before this PR); the rest are reasoned.

- F1 (window edge): failing input: `malicious_4_synthetic.json`: sign-up chain from 10:50Z, discovery at 11:05Z. The draft SPL used `bin _time span=60m`, which split the stages into two bins and returned 0 rows. Fix: `sort 0 _time | streamstats last(signup_time) BY sourceIPAddress`, then `_time-last_signup_time<=3600`. Replay: 1 row.
- F2 (order): failing input: `near_miss_5_synthetic.json`: discovery at 10:05Z, sign-up at 10:20Z, same clock hour. The draft SPL returned 1 row because a bin has no order. Fix: Only discovery events after a sign-up count (`discover_after_signup`). Replay: 0 rows.
- F3 (dead branch): failing input: Reasoned: draft filter `signup_fails>=3 OR signups>=1`; every failed sign-up is also a sign-up, so the first half never changes the result. Fix: Filter is `signups>=1 AND discovers_after_signup>=1`; `signup_fails` stays as output.
- F4 (scope): failing input: Reasoned: the draft set `is_signup` on any `eventName=SignUp`, and missed Hosted UI / managed login sign-ups. Fix: `is_signup` requires `cognito-idp.amazonaws.com` and accepts `SignUp`, `Signup_POST`, `signup_POST` (names from the Cognito CloudTrail page).

## Reviewer status
pending human review (merge approved by the repo owner in chat, 2026-11-12)
