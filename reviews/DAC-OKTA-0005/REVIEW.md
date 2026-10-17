# REVIEW — DAC-OKTA-0005 Okta: one session allowed from two IPs with different browser or OS

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_suspicious_use_of_a_session_cookie.yml (security_content develop @ d6afc62b750d)

## Coverage after
Groups Okta System Log policy.evaluate_sign_on events with outcome.result=ALLOW by authenticationContext.externalSessionId and user, and alerts when the same session is allowed from more than one client.ipAddress and the client.userAgent.browser or client.userAgent.os also changes. A stolen Okta session cookie replayed from another machine keeps the session id but brings a new IP and client. country_change=1 when client.geographicalContext.country differs. Built only from field paths and values in the Splunk attack_data sample okta_web_session_multiple_ip.log.

## ATT&CK mapping check (v19.2)
T1550.004 → lateral-movement. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1539/okta_web_session_multiple_ip/okta_web_session_multiple_ip.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `outcome.result`, `authenticationContext.externalSessionId`, `actor.alternateId`, `client.ipAddress`, `client.userAgent.browser`, `client.userAgent.os`, `client.userAgent.rawUserAgent`, `client.geographicalContext.country`, `target{}.displayName`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1539/okta_web_session_multiple_ip/okta_web_session_multiple_ip.log | 2 | 1 | 1 | `{"session": "idxiiDSIWJxR--Gvc_e3e6IXQ", "user": "user0315e2@example.com", "ip_count": 2, "src_ip": ["18.185.207.118", "23.93.1.1"], "browser": ["CHROME", "Mozilla"], "os": ["Mac OS 12.1.0 (Ventura)", "Mac OS 13.4.0 (Ventura)"], "country_change": 1}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (fidelity): comparing raw User-Agent strings fires when Chrome auto-updates mid-session (122.0.0.0 to 123.0.0.0) while the laptop changes network. Fix: compare client.userAgent.browser and client.userAgent.os (Okta-parsed); both differ in the payload (CHROME/Mozilla, Mac OS 13.4.0/12.1.0). Raw UA kept as a column.
- F2 (correctness): upstream groups by debugData.dtHash; Okta documents externalSessionId as the field that "identifies events that occurred in the same user session", so the session key is externalSessionId. dtHash is the same value in both payload events, so either fires here.
- F3 (every line needed): IP-only change is not enough (benign fixture: same client, new IP).

## Bypass table
| Attacker variation | Result |
|---|---|
| Replay the cookie with a spoofed identical User-Agent from a new IP | MISSED unless Okta parses a different OS/browser. Accepted to keep FPs down |
| Replay from an IP in the same NAT | MISSED |
| Use the stolen session only against apps (no new policy evaluation) | MISSED |

## False-positive check
- User moves between networks and browsers while one Okta session stays valid (rare: the session cookie lives in one browser). Corporate proxies that rewrite User-Agent.

## Unverified ideas
- Whether policy.evaluate_sign_on fires on every session reuse depends on the app sign-on policy re-evaluation; not verified in a tenant.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0005/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_ip_change_same_client | benign | False | 0 | PASS |
| near_miss_new_session_on_attacker_host | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
