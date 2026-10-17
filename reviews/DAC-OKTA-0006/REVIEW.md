# REVIEW — DAC-OKTA-0006 Okta: three or more Verify pushes denied for one user, with or without a later approval

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_mfa_exhaustion_hunt.yml (security_content develop @ d6afc62b750d)
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_multiple_failed_mfa_requests_for_user.yml (security_content develop @ d6afc62b750d)

## Coverage after
Counts Okta System Log user.authentication.auth_via_mfa events with debugContext.debugData.factor=OKTA_VERIFY_PUSH per actor.alternateId and alerts when debugContext.debugData.pushOnlyResponseType=OV_RESPONSE_DENY appears three or more times in the search window (60 minutes). Repeated denied pushes mean someone holding the password is spamming the user (MFA fatigue). approved_after_denies=1 when an OV_RESPONSE_APPROVE follows the first deny, i.e. the user probably gave in. Built only from field paths and values in the Splunk attack_data samples okta_multiple_failed_mfa_pushes.log and okta_multiple_failed_mfa_requests.log.

## ATT&CK mapping check (v19.2)
T1621 → credential-access. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_multiple_failed_mfa_pushes/okta_multiple_failed_mfa_pushes.log, https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_multiple_failed_mfa_requests/okta_multiple_failed_mfa_requests.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `debugContext.debugData.factor`, `debugContext.debugData.pushOnlyResponseType`, `actor.alternateId`, `authenticationContext.externalSessionId`, `client.ipAddress`, `outcome.result`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_multiple_failed_mfa_pushes/okta_multiple_failed_mfa_pushes.log | 20 | 1 | 1 | `{"user": "user15@splunkresearch.com", "denies": 7, "approvals": 2, "approved_after_denies": 1}` |
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_multiple_failed_mfa_requests/okta_multiple_failed_mfa_requests.log | 33 | 1 | 1 | `{"user": "user15@splunkresearch.com", "denies": 16, "approvals": 0, "approved_after_denies": 0}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (correctness, from the payload): upstream multiple_failed_mfa_requests filters outcome.result=FAILURE and factor!=PASSWORD_AS_FACTOR; in the pushes sample every OV_RESPONSE_DENY is FAILURE, so the deny value is the direct signal. Fix: key on pushOnlyResponseType=OV_RESPONSE_DENY, not outcome.reason (which says INVALID_CREDENTIALS for both bad passwords and denies).
- F2 (fidelity): counting push sends (system.push.send_factor_verify_push) counts normal pushes the user approves. Fix: count responses only; send events not needed.
- F3 (correctness): approval before the first deny (15:47 in the sample) must not set approved_after_denies. Fix: last_approve>first_deny.
- F4 (load): one row per user, no per-event output.

## Bypass table
| Attacker variation | Result |
|---|---|
| Pushes ignored rather than denied | MISSED (no response event in the samples) |
| Spread pushes over more than 60 minutes | MISSED |
| Number-challenge push | Unverified: different response field |

## False-positive check
- A user repeatedly denying pushes they triggered themselves on a second device by mistake. Low volume; confirm with the user.

## Unverified ideas
- Threshold 3 denies / 60 minutes is judgement; both samples have 7 and 16 denies.
- The okta_multiple_failed_mfa_requests sample (16 denies in ~2.5 minutes) is covered by this rule; no separate rule was built for it.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0006/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_two_stray_denies | benign | False | 0 | PASS |
| near_miss_password_failures_only | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
