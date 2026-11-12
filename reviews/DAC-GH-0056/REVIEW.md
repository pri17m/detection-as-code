# REVIEW - DAC-GH-0056 GitHub: one actor pushes or opens pull requests in 5+ repos within 60 minutes, 2+ not owned by them

## Attribution
Behaviour from Aikido Security (12 Nov 2026): https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories. Aikido reports "4,837 compromised accounts opened probe pull requests in 61,764 repositories", that "10,431 of the pull requests went into repositories the account doesn't own, reached through collaborator or organisation access", and that the probe PR "is followed by commits that carry the real payload." Event and field names are from GitHub's org audit log events page and "Identifying audit log events performed by an access token". Own SPL. No employer, client or tenant data. Fixtures are synthetic.

## As-is (new)
New rule. No rule on `main` uses `pull_request.create`. DAC-GH-0012 was a stub with no logic (fixed in its own PR). DAC-GH-0030 counts clones, not pushes or PRs.

## After
`git.push` and `pull_request.create` from non-bot actors (drops `actor_is_bot=true` and names ending `[bot]`). A 60-minute sliding window per actor (`streamstats time_window=60m`) counts distinct repos and distinct repos whose owner (the part of `repo` before `/`) is not the actor. Alerts when the window holds 5+ repos and 2+ not owned. Critical when 5+ PRs in that window share one title, which is the probe pattern Aikido describes. One row per actor with the repos, actions, PR titles, token hashes, token types and user agents. Thresholds are unmeasured. `telemetry_validated: false`.

`git.*` events are "not available in the web interface, only via the REST API, audit log streaming, or JSON/CSV exports", and on Enterprise Cloud the REST API keeps them for 7 days (GitHub docs).

## ATT&CK v19.2
T1078 (stealth, persistence, privilege-escalation, initial-access), T1677 (execution). Checked against enterprise-attack-19.2.json: both present, not revoked or deprecated.

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Slow down to 4 repos per hour | MISSED (threshold) | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |
| Spread across many orgs, few repos in each | MISSED per org: each org audit log only sees its own repos | https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization |
| Use a GitHub App token, so the actor is `something[bot]` | MISSED: bots are excluded to cut Renovate/Dependabot noise | https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/identifying-audit-log-events-performed-by-an-access-token |
| Only personal repos owned by the actor | MISSED: needs 2+ repos not owned | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |
| Burst that crosses a clock-hour boundary | Caught: sliding window, see F1 | (fixture malicious_1) |

## Unverified
- That `pull_request_title` is filled in on streamed `pull_request.create` events. It's listed as an additional field in the docs.
- That `actor_is_bot` is present and boolean in real streams.
- Whether `git.push` carries `repo` in the same `owner/name` form as other events.
- The sourcetypes `github:audit` and `github:cloud:audit` match the existing DAC-GH rules but are not in `config/sourcetype_map.yaml` (the validator only enforces that list for Windows). The allowlist was not edited.

## Tests / fixtures
`tests/cases/DAC-GH-0056/`: all synthetic.

Splunk Enterprise 9.4.1 (throwaway local instance on the agent box). No Splunk add-ons installed, so a local props.conf set `KV_MODE = json` for the sourcetype (`aws:cloudtrail` timestamps from `eventTime`, `github:audit` timestamps from `@timestamp` in epoch ms). Field names are the raw JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -index dac`, and the rule query ran unchanged via REST (`search index=dac source="<fixture>" <query>`, earliest=0). The events are synthetic, so this shows the SPL parses and the logic does what each fixture says. It says nothing about real volume or real field shapes. CI does not run fixtures (the repo has no Splunk runner).

| Fixture | Label | Expect alert | Rows | Result | Rows with the draft SPL | What it is |
|---|---|---|---|---|---|---|
| malicious_0_synthetic.json | malicious | True | 1 | PASS | 0 | Same probe PR title plus a push into 6 repos in 24 min, 4 not owned (critical) |
| malicious_1_synthetic.json | malicious | True | 1 | PASS | 0 | Pushes only, 5 repos between 13:50 and 14:34 UTC |
| benign_2_synthetic.json | benign | False | 0 | PASS | 0 | `renovate[bot]` opens 8 PRs; a developer pushes to 3 repos |
| near_miss_3_synthetic.json | near_miss | False | 0 | PASS | 0 | 6 repos but only 1 not owned; 5 org PRs spread over 80 min |

## Ponytail findings
Ponytail pass (2026-11-12). Findings naming a fixture were replayed in local Splunk against the pre-fix draft.

- F1 (window edge): failing input: `malicious_0_synthetic.json` (12:45 to 13:09 UTC) and `malicious_1_synthetic.json` (13:50 to 14:34 UTC). The draft used `bin _time span=60m` and missed both, because each burst crossed a clock hour. Fix: `sort 0 _time | streamstats time_window=60m ... BY actor`. Replay: 1 row each.
- F2 (one row per actor): reasoned. `streamstats` flags every event once the window is over threshold. The final `stats ... BY actor` folds those into one alert per actor.
- F3 (case): reasoned. GitHub logins are case-insensitive, so owner and actor are compared in lower case.

## Reviewer status
pending human review
