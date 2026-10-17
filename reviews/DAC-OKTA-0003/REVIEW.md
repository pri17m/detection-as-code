# REVIEW — DAC-OKTA-0003 Okta: Verify push denied for a sign-in from a new device and new IP

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_mismatch_between_source_and_response_for_verify_push_request.yml (security_content develop @ d6afc62b750d)

## Coverage after
Correlates, per authenticationContext.externalSessionId, Okta System Log system.push.send_factor_verify_push events whose debugContext.debugData.behaviors has New Device=POSITIVE and New IP=POSITIVE with a user.authentication.auth_via_mfa response (debugContext.debugData.factor=OKTA_VERIFY_PUSH) where debugContext.debugData.pushOnlyResponseType=OV_RESPONSE_DENY. The real user rejecting a push raised by an unfamiliar device and IP is a strong sign someone else has the password. ip_mismatch=1 when the response came from an IP that never requested a push; approved_after_deny=1 when a later push in the same session was approved (likely MFA fatigue success). Built only from field paths and values in the Splunk attack_data sample okta_mismatch.log.

## ATT&CK mapping check (v19.2)
T1621 → credential-access. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_mismatch/okta_mismatch.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `outcome.result`, `authenticationContext.externalSessionId`, `client.ipAddress`, `actor.alternateId`, `debugContext.debugData.factor`, `debugContext.debugData.pushOnlyResponseType`, `debugContext.debugData.behaviors`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_mismatch/okta_mismatch.log | 12 | 1 | 1 | `{"session": "zzxTuSsen_TRk-zzN3ISn3Ozz", "pushes": 4, "denies": 1, "approvals": 1, "push_ip": ["49.208.55.61"], "responder_ip": ["117.99.201.94", "118.99.201.94"], "ip_mismatch": 1, "approved_after_deny": 1}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (correctness, from the payload): upstream line 1 (the OV_RESPONSE_APPROVE response) is invalid JSON ("id": 9f59...""), so Splunk JSON extraction will not produce its fields. Fix: the alert condition needs only the push behaviors and the deny; approval is a ranking column. Matched with the line dropped and with it repaired (see the Payload match table).
- F2 (fidelity): "push IP differs from response IP" alone fires for every user whose phone is on mobile data while the laptop is on Wi-Fi. Failing input: push from 10.0.0.5 office NAT, approve from carrier IP. Fix: ip_mismatch is a column, not a filter; the filter is deny + New Device/New IP on the push.
- F3 (correctness): denies counted with count(deny_time) on the response events only; a push event never carries pushOnlyResponseType in the payload, but is_push=0 is required anyway so a future field on pushes cannot count as a deny.

## Bypass table
| Attacker variation | Result |
|---|---|
| Push sent from an attacker host Okta does not flag as new (e.g. residential proxy near the victim) | MISSED if behaviors are NEGATIVE; see DAC-OKTA-0006 for repeated denies |
| User ignores pushes instead of denying | MISSED (no response event) |
| Number-challenge push | Unverified: pushWithNumberChallengeResponseType is a different field; deny value not in payload |

## False-positive check
- User signs in on a new laptop on a new network, then taps Deny by mistake. Confirm with the user; a single deny with no approval and no further pushes is the usual benign shape.

## Unverified ideas
- debugData.behaviors may be absent or carried in logOnlySecurityData in some orgs (seen in Elastic test data); then push_new_dev_ip=0 and the rule is silent.
- Window: run over 60 minutes; sessions longer than that split.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0003/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_push_approved_known_device | benign | False | 0 | PASS |
| near_miss_deny_but_known_device | near_miss | False | 0 | PASS |
| near_miss_new_device_no_deny | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
