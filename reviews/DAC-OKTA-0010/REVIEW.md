# REVIEW — DAC-OKTA-0010 Okta: user reported suspicious activity on their account

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_suspicious_activity_reported.yml (security_content develop @ d6afc62b750d)

## Coverage after
Detects Okta System Log user.account.report_suspicious_activity_by_enduser events (the user clicked "report suspicious activity" in an Okta security notification). Surfaces the reported event from debugContext.debugData.suspiciousActivityEventType, its IP, location and transaction id so the analyst can pivot straight to the reported event. This is a passthrough of a user report, not behavioural logic, but the user saying "this was not me" is a high-signal input. Built only from field paths and values in the Splunk attack_data sample okta_suspicious_activity_reported_by_user.log.

## ATT&CK mapping check (v19.2)
T1078.004 → initial-access, persistence, privilege-escalation, stealth. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/okta_suspicious_activity_reported_by_user/okta_suspicious_activity_reported_by_user.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `actor.alternateId`, `client.ipAddress`, `debugContext.debugData.suspiciousActivityEventType`, `debugContext.debugData.suspiciousActivityEventIp`, `debugContext.debugData.suspiciousActivityEventCity`, `debugContext.debugData.suspiciousActivityEventCountry`, `debugContext.debugData.suspiciousActivityEventTransactionId`, `debugContext.debugData.suspiciousActivityTimestamp`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/okta_suspicious_activity_reported_by_user/okta_suspicious_activity_reported_by_user.log | 1 | 1 | 1 | `{"user": "user15@splunkresearch.com", "reported_event": "system.email.mfa_reset_notification.sent_message", "reported_ip": "120.1.121.43", "reported_txn": "5e32024c5d1d1ed06a7d7d7bcce98d24"}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (triage, from the payload): the reported transaction id 5e32024c5d1d1ed06a7d7d7bcce98d24 is the transaction.id of the three factor resets in the DAC-OKTA-0001 sample (system.email.mfa_reset_notification.sent_message). Fix: emit reported_transaction so the analyst can pivot with transaction.id=<value>.
- F2 (every line needed): no outcome filter; the sample outcome is SUCCESS and a report is meaningful regardless.
- Low value as logic (vendor/user passthrough), kept because a user report is a high-signal trigger and the payload exists.

## Bypass table
| Attacker variation | Result |
|---|---|
| User does not read the notification | MISSED (by design) |
| Attacker changes the user's email first so notifications go elsewhere | MISSED |

## False-positive check
- User reports a legitimate change made by the help desk (for example an MFA reset they forgot they asked for). Confirm with the actor of the reported transaction.

## Unverified ideas
- Which Okta notifications carry the report link depends on org settings (End-user notifications / Suspicious activity reporting); not verified.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0010/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_other_user_event | benign | False | 0 | PASS |

## Reviewer status: pending human approval
