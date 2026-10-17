# REVIEW — DAC-OKTA-0011 Okta: new unmanaged Okta Verify device enrolled on an account

## Coverage before
No Okta rules on main (no `OktaIM2:log` detections). Open, unmerged: DAC-OKTA-0001..0010 (PRs #66-#75); none covers device enrolment. DAC-OKTA-0001 (MFA factors reset) is the closest. Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_new_device_enrolled_on_account.yml (security_content develop @ d6afc62b750d)

## Coverage after
Detects successful Okta System Log device.enrollment.create events ("Enroll new device") and returns one row per actor and enrolled device, taken from the target element whose type is UDDevice. Okta documents this event as a new device registered for Okta Verify. An attacker who has a user's password or session can enrol their own phone as an Okta Verify authenticator and then approve their own push challenges (T1098.005 Device Registration). Devices whose target detailEntry.managed is not "false" are dropped, so MDM-managed corporate enrolments do not alert. Triage columns: devices_enrolled_by_actor / multi_device=1 when one actor enrols two or more devices in the search window, and via_proxy=1 when securityContext.isProxy is not "false"; rows are sorted with those first. Built only from field paths and values in the Splunk attack_data sample okta_new_device_enrolled.log. Run hourly over the last 24 hours and throttle on device_id.

## ATT&CK mapping check (v19.2)
T1098.005 → persistence, privilege-escalation. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.005/okta_new_device_enrolled/okta_new_device_enrolled.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `outcome.result`, `actor.id`, `actor.alternateId`, `target{}.id`, `target{}.type`, `target{}.displayName`, `target{}.detailEntry.managed`, `target{}.detailEntry.osPlatform`, `target{}.detailEntry.deviceStatus`, `client.ipAddress`, `client.geographicalContext.country`, `securityContext.asOrg`, `securityContext.isProxy`, `authenticationContext.externalSessionId`, `debugContext.debugData.requestUri`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.005/okta_new_device_enrolled/okta_new_device_enrolled.log | 2 | 2 | 2 | `{"actor_id": "00udumbe8xQoWoPtg5d7", "actor": "user14@splunkresearch.com", "device_id": "guofgmdwohKN0DZ2h5d7", "device_name": ["OnePlus 7T"], "os_platform": ["ANDROID"], "managed": ["false"], "src_ip": ["120.1.210.147"], "via_proxy": 0, "devices_enrolled_by_actor": 1, "multi_device": 0}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (fidelity): upstream alerts on every device.enrollment.create, including MDM-managed corporate phones pushed by IT. Failing input: benign_mdm_managed_device (detailEntry.managed="true") would alert. Fix: keep only devices where detailEntry.managed is "false" or absent; absent is kept so a schema change fails open, not closed.
- F2 (correctness): picking device fields with mvindex('target{}.detailEntry.managed', mvfind('target{}.type',...)) misaligns when another target element has no detailEntry (the {} lists skip missing keys). Fix: spath target{} + mvexpand and read each element's own type/id/detailEntry; cheap because device.enrollment.create is low volume and the base search is filtered first.
- F3 (triage/load): one actor enrolling several phones in a day (attacker adding devices, or a stolen account used to register many) came out as unrelated rows. Fix: eventstats dc(device_id) by actor.id, multi_device=1 sorted first. Not a filter: the payload has one device per actor and a single attacker device is the main case.
- F4 (every line needed): via_proxy uses only the literal "false" seen in the payload; any other value (true) or a missing field defaults to 0 via coalesce, so a missing field never raises priority.
- F5 (correctness): stats drops rows whose by-key is null; fillnull device_id="unknown" so a UDDevice element without id still alerts.
- F6 (cross-check): rule produces 0 rows on the other 15 parsed attack_data Okta payloads (no device.enrollment.create events there).

## Bypass table
| Attacker variation | Result |
|---|---|
| Enrol the attacker phone as an MDM-managed device | MISSED by design (requires enrolment into the victim org's MDM, which itself logs elsewhere) |
| Enrol a non-Okta-Verify factor (SMS, TOTP app, security key) instead of a device | MISSED: those log user.mfa.factor.activate, which has no attack_data payload, so not built (see DAC-OKTA-0012 skip note) |
| Use device.token.enrollment.create to add a second Okta Verify device from an existing enrolment | Only the final device.enrollment.create is caught; the token event is not in scope |
| Enrol during a normal-looking sign-in from the victim's region | Still alerts (no IP/geo filter); triage relies on analyst confirmation |

## False-positive check
- A user replacing or adding a personal (BYOD, unmanaged) phone for Okta Verify. Confirm with the user out of band (not via the new device), check that the enrolment followed a normal sign-in from their usual IP/ASN, and look for a help-desk ticket. Expect roughly one alert per unmanaged phone change per user.

## Unverified ideas
- The payload only shows target detailEntry.managed="false"; the Okta event-type catalogue lists name, status, serialNumber, imei, meid, osVersion and osPlatform as target details but does not document a managed="true" value. If every enrolment logs "false", F1 filters nothing and the rule alerts on every enrolment.
- No real benign enrolment events were available; FP volume is not measured.
- Okta Identity Engine also writes user.mfa.factor.activate when Okta Verify is enrolled (Okta event-type catalogue); correlating the two is not possible without a payload.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Related: MFA factor enrolment (DAC-OKTA-0012) not built
Requested alongside this rule. No real payload exists, so per the payload-only rule it was not built. Searched on 2026-10-17:
- splunk/attack_data master tree (GitHub API, recursive, not truncated): 17 Okta files, all already used here; none named for factor activation/enrolment. Non-Okta MFA-registration datasets exist (azure_ad_register_new_mfa_method, o365_register_new_mfa_method, aws_new_mfa_method_registered_for_user) but are other sourcetypes.
- splunk/security_content develop @ d6afc62b750d: no detection or story references user.mfa.factor.activate, system.mfa.factor.activate, user.mfa.factor.update or factor.reset_all; the only `user.mfa.factor.*` reference is user.mfa.factor.deactivate (okta_multi_factor_authentication_disabled.yml).
- All 17 downloaded Okta payloads: eventTypes seen are listed in the PR; no factor activate/update/enrol events ("AuthenticatorEnrollment" appears only as a target type on authentication events).

## Tests
`tests/cases/DAC-OKTA-0011/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_mdm_managed_device | benign | False | 0 | PASS |
| near_miss_failed_enrollment | near_miss | False | 0 | PASS |
| near_miss_enrollment_token_event | near_miss | False | 0 | PASS |
| near_miss_target_not_uddevice | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
