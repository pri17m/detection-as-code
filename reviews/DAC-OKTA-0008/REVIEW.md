# REVIEW — DAC-OKTA-0008 Okta: three or more accounts locked out from one IP in 30 minutes

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_multiple_accounts_locked_out.yml (security_content develop @ d6afc62b750d)

## Coverage after
Counts Okta System Log user.account.lock events with outcome.reason=LOCKED_OUT per client.ipAddress in 30-minute bins and alerts when three or more distinct actor.id values are locked. Several lockouts from one source means a password attack crossed the lockout threshold on multiple accounts. Built only from field paths and values in the Splunk attack_data sample okta_multiple_accounts_lockout.log.

## ATT&CK mapping check (v19.2)
T1110 → credential-access. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110/okta_multiple_accounts_lockout/okta_multiple_accounts_lockout.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `outcome.reason`, `client.ipAddress`, `actor.id`, `actor.alternateId`, `securityContext.asOrg`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110/okta_multiple_accounts_lockout/okta_multiple_accounts_lockout.log | 7 | 1 | 1 | `{"src_ip": "120.1.121.43", "locked_users": 6}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (correctness, from the payload): two lockouts share actor.id AUrSm5axYHCjeTmkEeNY but have different logins (user20/user21). dc(actor.alternateId)=7, dc(actor.id)=6. actor.id is Okta's stable user id, so it is the count key; both pass the threshold.
- F2 (every line needed): outcome.result is FAILURE on every lockout in the sample and adds nothing over outcome.reason=LOCKED_OUT; dropped.

## Bypass table
| Attacker variation | Result |
|---|---|
| Distribute attempts across IPs | MISSED |
| Stay under the lockout threshold | MISSED; see DAC-OKTA-0007 |

## False-positive check
- Shared kiosk or office NAT after a password policy change. Check securityContext.asOrg against your own egress ranges.

## Unverified ideas
- Threshold 3 / 30 minutes is judgement; the sample has 6 users in one second.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0008/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_two_lockouts | benign | False | 0 | PASS |
| near_miss_three_lockouts_three_ips | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
