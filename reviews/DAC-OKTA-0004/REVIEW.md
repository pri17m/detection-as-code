# REVIEW — DAC-OKTA-0004 Okta: new API token created

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_new_api_token_created.yml (security_content develop @ d6afc62b750d)

## Coverage after
Detects successful Okta System Log system.api_token.create events. Okta documents this event as generating an unscoped API token that grants authenticated access to the org API, so a token minted by a compromised admin is durable access that survives password and MFA resets. Token name and id come from the target of type Token. Built only from field paths and values in the Splunk attack_data sample okta_new_api_token_created.log.

## ATT&CK mapping check (v19.2)
T1098.001 → persistence, privilege-escalation. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.001/okta_new_api_token_created/okta_new_api_token_created.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `outcome.result`, `actor.id`, `actor.alternateId`, `target{}.id`, `target{}.type`, `target{}.displayName`, `client.ipAddress`, `client.userAgent.rawUserAgent`, `authenticationContext.externalSessionId`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.001/okta_new_api_token_created/okta_new_api_token_created.log | 1 | 1 | 1 | `{"actor": "user15@splunkresearch.com", "token_name": "testing", "token_id": "00T1r1xfljWsN50A25d7", "src_ip": "120.1.121.43"}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (every line needed): no threshold or allowlist; the event is rare and high impact, and an allowlist of "integration admins" would hide exactly the compromised admin case.
- F2 (triage): raw target{}.displayName mixes all targets. Fix: token_name/token_id picked from the target whose type is Token.

## Bypass table
| Attacker variation | Result |
|---|---|
| Create an OAuth service app with client credentials instead of an API token | MISSED (different event type, no payload) |
| Steal an existing token | MISSED |

## False-positive check
- Admins creating tokens for a new integration. Confirm a change record and that the token name matches a known integration; expected volume is low.

## Unverified ideas
- Scoped OAuth tokens and service apps log other event types; not covered.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0004/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| near_miss_token_create_failed | near_miss | False | 0 | PASS |
| benign_other_token_event | benign | False | 0 | PASS |

## Reviewer status: pending human approval
