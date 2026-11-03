# REVIEW — DAC-OKTA-0013 Okta: sign-in for a nonexistent username then a privileged username from the same IP

## As-is
New rule. No existing rule on main or in open PRs uses this sequence. Closest open PRs: DAC-OKTA-0007 (five or more users fail sign-in from one IP in 10 minutes, PR #72) and DAC-OKTA-0008 (lockouts from one IP, PR #73). Both count volume; this rule needs only two events, so it catches the low-and-fast agent pattern those thresholds miss.

## Coverage after
Alerts when one `client.ipAddress` makes an Okta `user.session.start` attempt for an unknown username (`actor.id="unknown"`) and, within 60 s, an attempt for a common privileged username (admin, administrator, root, superadmin, sysadmin, okta-admin; matched on the part before "@"). `priv_success=1` marks a successful privileged sign-in and is sorted first.

## Source behaviour (Unit 42, opened 2026-11-03)
https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-10-30-activity-using-ARTEX-agentic-AI.txt
- Line 58: "Log in as a randomly generated, nonexistent user to baseline the error response, followed one second later by a login as \"admin\""
- Line 160 (hunting guidance): "Identity-provider logins for usernames beginning with \"zz\", or containing \"nonexistent\" / \"not-a-user\", followed within seconds by \"admin\" or other privileged usernames"
- IOC usernames (lines 108-110): zz_no_such_user_9f3a@<victim domain>, zzq.nonexistent9x7@<victim domain>, precheck.not-a-user@example[.]invalid
- Note: Unit 42 says "identity-provider" and does not name Okta. Mapping this to Okta is my inference.

## Telemetry and fields
- `user.session.start`: "Attempt to authenticate a user or establish an Okta session… including failures before credentials are checked" (https://developer.okta.com/docs/okta-event-types.csv).
- Unknown user: Okta Support says that on a VERIFICATION_ERROR the DisplayName and ID show `unknown` when "the user does not exist" (https://support.okta.com/help/s/article/okta-system-log-displays-verification-error-due-to-incorrect-username). Common failures list: UNKNOWN_USER, INVALID_CREDENTIALS (https://support.okta.com/help/s/article/common-okta-login-failures).
- LogEvent fields `actor.id`, `actor.alternateId`, `client.ipAddress`, `client.userAgent.rawUserAgent`, `outcome.result`, `outcome.reason`, `securityContext.isProxy`, `request.ipChain` exist in Okta's OpenAPI LogEvent schema (https://raw.githubusercontent.com/okta/okta-management-openapi-spec/master/dist/current/management-minimal.yaml).
- Sourcetype `OktaIM2:log` = "System log events coming from Okta Rest API endpoints" (https://splunk.github.io/splunk-add-on-for-okta-identity-cloud/Sourcetypes/).
- Clean-room: own SPL, written from the Unit 42 behaviour text. No vendor query copied.

## ATT&CK mapping check (v19.2)
Checked against enterprise-attack-19.2.json (mitre-attack/attack-stix-data):
- T1110 Brute Force → credential-access. Not revoked or deprecated. Mapped.
- T1078 Valid Accounts (stealth, persistence, privilege-escalation, initial-access): **not mapped**. The rule fires on the attempt; a successful privileged sign-in (`priv_success=1`) is only a triage flag, not the trigger.

## Ponytail review
- F1 (correctness): if "admin" does not exist in the org, it is also `actor.id="unknown"` and counted as its own probe, so it would match itself. Failing input: a single `admin@x` event with actor.id=unknown → 1 row. Fix: `is_probe` requires `is_priv=0`.
- F2 (order): eventstats by IP would also alert when admin comes BEFORE the fake user. Failing input: near_miss_admin_before_probe. Fix: `sort 0 _time` + `streamstats last(probe_time) by src_ip`, so only earlier probes count.
- F3 (correctness): matching the full alternateId against `^admin$` misses `admin@victim.com`, which is the form Unit 42 shows. Failing input: malicious_fake_user_then_admin with full UPNs → 0 rows. Fix: compare `local_part` (text before "@"), lower-cased.
- F4 (null safety): events without `client.ipAddress` would group under null and pair unrelated users. Fix: `isnotnull(src_ip)`.
- F5 (load): the base search keeps only `user.session.start`, then drops every event that is neither a probe nor privileged before the sort, so the sort sees a small set.
- F6 (every line needed): `last_probe_user` gives the analyst the fake username to compare against the Unit 42 IOCs; `priv_success` ranks real compromise first.

## Bypass research
| Attacker variation | Result | Source / note |
|---|---|---|
| Probe and admin attempt from different IPs (rotating proxies; Unit 42 lists 4+ IPs) | MISSED: rule keys on one IP | Unit 42 file, IP IOCs |
| Wait more than 60 s between probe and admin | MISSED: window is 60 s (tunable) | Unit 42 reports ~1 s and 25-31 s think pauses (same file), so 60 s covers the reported cadence |
| Use a privileged name not in the list (e.g. `it-admin`, `okta.admin`) | MISSED: fixed list | Tune list per org |
| Enumerate real usernames first (no unknown user) | MISSED: needs `actor.id="unknown"` | DAC-OKTA-0007 (spray) may catch volume |
| Traffic through a proxy/CDN so Okta sees the proxy IP | Partly: `client.ipAddress` may be the proxy; `request.ipChain` holds the chain | Okta OpenAPI LogEvent schema (`LogRequest.ipChain`); not used here |
| Probe through a non-Okta login page (the app itself) | MISSED: not in Okta logs | Needs web/WAF logs |

## False-positive check
See rule `false_positives`: a mistyped username then a shared admin account from the same NAT; busy NAT/proxy egress IPs; authorised pentests and SSO tests. Volume not measured.

## Unverified
- Splunk field naming: dotted raw paths (`actor.id`, `client.ipAddress`) for `OktaIM2:log` come from DAC-OKTA-0011's attack_data payload and a community README (https://github.com/mbegan/Okta-Identity-Cloud-for-Splunk/blob/master/README/user.session.start.md), not Splunk docs.
- `actor.id="unknown"` for nonexistent users is from an Okta Support article and the community README; Okta's developer docs do not specify it. Whether Identity Engine orgs log it the same way is not confirmed.
- Whether `outcome.reason` is VERIFICATION_ERROR or UNKNOWN_USER for unknown users in the System Log is not confirmed; the rule does not depend on it.
- 60 s window and username list are judgement, not measured.
- No real Okta payload with this sequence exists; all fixtures are synthetic.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes). The validator does not enforce the allowlist for non-Windows sourcetypes, so CI passes without it.

## Tests
`tests/cases/DAC-OKTA-0013/`: all fixtures synthetic (hand-written, RFC 5737 IPs, no real or employer data). Not run by CI (no Splunk runner). Local Python stand-in:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| malicious_fake_user_then_admin | malicious | True | 1 | PASS |
| malicious_fake_user_then_real_admin_success | malicious | True | 1 | PASS |
| benign_normal_admin_signin | benign | False | 0 | PASS |
| near_miss_outside_window | near_miss | False | 0 | PASS |
| near_miss_different_ip | near_miss | False | 0 | PASS |
| near_miss_admin_before_probe | near_miss | False | 0 | PASS |
| near_miss_known_user_typo_password | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
