# REVIEW - DAC-GH-0012 GitHub: Human-owned PAT used for bursty API automation

## Attribution
Field names from GitHub's "Identifying audit log events performed by an access token" (`hashed_token`, `programmatic_access_type`, `token_scopes`): https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/identifying-audit-log-events-performed-by-an-access-token, and the common-fields list on the org audit events page. The burst case is from the Aikido CI-stealer write-up: https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories. Own SPL. No employer, client or tenant data. Fixtures are synthetic.

## As-is
`search action="*" | # Experimental stub: ... | table ...`. There was no logic, and Splunk 9.4.1 rejected the `| #` line ("Missing a search command before '#'"), so it errored on every run.

## After
The title can be expressed with documented fields, so it now has real logic. Events with a `hashed_token` whose `programmatic_access_type` contains "personal access token", from non-bot actors, are counted per token in a sliding 10-minute window. Alerts when one token reaches 50+ audited events or 10+ repos in the window. One row per token with actors, actions, repo counts, scopes and user agents. Thresholds are unmeasured. `telemetry_validated: false`. Tags kept; `aikido-wfx` and `fixed-2026-11-12` added.

## ATT&CK v19.2
T1550.001 (lateral-movement), unchanged. Checked against enterprise-attack-19.2.json: present, not revoked or deprecated.

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Stay under 50 events and 10 repos per 10 minutes | MISSED (threshold) | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |
| Use an OAuth app or GitHub App user token instead of a PAT | MISSED: only PAT types are counted | https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/identifying-audit-log-events-performed-by-an-access-token |
| Read-heavy automation (clones, API reads) | Mostly MISSED: the audit log records audited actions, not every API read | https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization |
| Several stolen PATs for one account | Each token is judged on its own | (design) |

## Unverified
- The exact `programmatic_access_type` strings. GitHub's docs name the field but don't list values. Fixtures use "Personal access token (classic)"; the regex is case-insensitive "personal access token".
- Whether `hashed_token` is present on git events in streams (the docs say Git events need export to identify by token).
- The sourcetypes `github:audit` and `github:cloud:audit` are kept from the original rule; they are not in `config/sourcetype_map.yaml` (the validator only enforces that list for Windows). The allowlist was not edited.

## Tests / fixtures
`tests/cases/DAC-GH-0012/`: all synthetic.

Splunk Enterprise 9.4.1 (throwaway local instance on the agent box). No Splunk add-ons installed, so a local props.conf set `KV_MODE = json` for the sourcetype (`aws:cloudtrail` timestamps from `eventTime`, `github:audit` timestamps from `@timestamp` in epoch ms). Field names are the raw JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -index dac`, and the rule query ran unchanged via REST (`search index=dac source="<fixture>" <query>`, earliest=0). The events are synthetic, so this shows the SPL parses and the logic does what each fixture says. It says nothing about real volume or real field shapes. CI does not run fixtures (the repo has no Splunk runner).

| Fixture | Label | Expect alert | Rows | Result | Rows with the as-is query | What it is |
|---|---|---|---|---|---|---|
| malicious_0_synthetic.json | malicious | True | 1 | PASS | error | 60 actions across 6 repos in 8 min from one PAT |
| malicious_1_synthetic.json | malicious | True | 1 | PASS | error | 20 actions across 10 repos in 9 min |
| benign_2_synthetic.json | benign | False | 0 | PASS | error | 80 actions from a GitHub App `[bot]` token |
| near_miss_3_synthetic.json | near_miss | False | 0 | PASS | error | 45 actions across 9 repos in 10 min from a PAT |

## Ponytail findings
- F1 (does not parse): failing input: any fixture. The as-is query errored on `| #`. Fix: rewritten without it.
- F2 (stub): failing input: `malicious_0_synthetic.json`. `action="*"` plus `table` has no condition, so on a working parser it would return every event. Fix: per-token sliding-window thresholds.
- F3 (window edge): reasoned. A sliding `streamstats time_window=10m` is used instead of fixed bins, so bursts that cross a bin edge still count. That's the same lesson as DAC-GH-0056 F1.
- F4 (author): the author stays "Detection Engineer" while the repo-wide author cleanup is on hold.

## Reviewer status
pending human review
