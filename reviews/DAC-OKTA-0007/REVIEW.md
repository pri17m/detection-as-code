# REVIEW — DAC-OKTA-0007 Okta: five or more users fail sign-in from one IP in 10 minutes (password spray)

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_multiple_users_failing_to_authenticate_from_ip.yml (security_content develop @ d6afc62b750d)

## Coverage after
Counts Okta System Log user.session.start events with outcome.result=FAILURE and outcome.reason=INVALID_CREDENTIALS per client.ipAddress in 10-minute bins and alerts when five or more distinct actor.alternateId values fail with no more than three failures per user on average (spray shape: few tries across many accounts, not one locked-out user). Built only from field paths and values in the Splunk attack_data sample okta_multiple_users_from_ip.log.

## ATT&CK mapping check (v19.2)
T1110.003 → credential-access. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/okta_multiple_users_from_ip/okta_multiple_users_from_ip.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `outcome.result`, `outcome.reason`, `client.ipAddress`, `actor.alternateId`, `client.userAgent.rawUserAgent`, `securityContext.asOrg`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/okta_multiple_users_from_ip/okta_multiple_users_from_ip.log | 13 | 1 | 1 | `{"src_ip": "120.1.121.43", "users": 10, "failures": 10}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (correctness, from the payload): the sample also has user.authentication.auth_via_mfa FAILURE events for the same users and IP (password-as-factor). Counting both would double count users 1-3. Fix: user.session.start only.
- F2 (fidelity): many failures for one user from one IP is brute force, not spray, and is already noisy. Fix: failures_per_user<=3.
- F3 (load): bin + stats by IP, one row per IP per bin.

## Bypass table
| Attacker variation | Result |
|---|---|
| Spray from many IPs (residential proxies), one user each | MISSED |
| Fewer than 5 users per 10 minutes (low and slow) | MISSED |
| Spray across a bin boundary | Split across two bins; may fall below 5 in each |

## False-positive check
- Large office or VPN egress IP where several users mistype passwords in the same 10 minutes (e.g. after a forced password change). Check securityContext.asOrg against your own egress ranges.

## Unverified ideas
- Threshold 5 users / 10 minutes is judgement; the sample has 10 users in one minute.
- Failures for non-existent logins: how Okta fills actor.alternateId is not in the sample.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0007/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_four_users_mistype | benign | False | 0 | PASS |
| near_miss_one_user_brute_force | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
