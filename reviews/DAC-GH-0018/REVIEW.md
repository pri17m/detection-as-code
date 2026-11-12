# REVIEW - DAC-GH-0018 GitHub: Workflow run with elevated permissions after unreviewed edit

## Attribution
Event-name check against GitHub's "Audit log events for your organization" (https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization) and the enterprise list (https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise), pulled 2026-11-12. Prompted by the Aikido CI-stealer research (https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories), where workflow file injection is the main payload path. No employer, client or tenant data.

## As-is
`search action IN ("workflows.update","workflows.created","repo.update") | search name="*.yml" OR ...`

The action names (workflows.update, workflows.created, repo.update (same query as DAC-GH-0017)) are not on GitHub's org or enterprise audit-log event lists. The query can't match real audit-log data, so the rule never fires.

## After
Tag `needs-review` appended to the existing tags. One sentence added to the description. Query, ID, ATT&CK, author and everything else unchanged.

Status: **needs-review**. The behaviour is an unreviewed workflow edit followed by a privileged run. GitHub's audit log records `git.push` with `external_id`, `repository_public`, `transport_protocol` and `transport_protocol_name` as extra fields, but not which files a push changed, and no `workflows.*` event records a workflow file being added or edited (the documented workflows actions cover runs, jobs, enable/disable and pin). So the behaviour can't be expressed with audit-log data alone. Following the brief, I didn't invent event names and didn't delete or renumber the rule.

## Options for the reviewer
- Option A (preferred): add a push-webhook source (`push` event, `commits[].added` / `commits[].modified`, `pusher`, `ref`; https://docs.github.com/en/webhooks/webhook-events-and-payloads#push) and rewrite against it. That needs a new sourcetype in `config/sourcetype_map.yaml`, which I haven't touched.
- Option B: the "privileged run" half can be expressed today with `workflows.prepared_workflow_job` (`secrets_passed`, `environment_name`, `job_workflow_ref`). Only the "after an unreviewed edit" half needs file or PR-review data (`pull_request_review.submit` exists, but linking a review to the workflow file still needs paths). I didn't build half a rule under this title.
- Option C: keep it as a documented gap until a file-level source exists.

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Any workflow file change (the Aikido `ci: refresh build cache` and `build-audit-xxxxxx.yml` variants) | MISSED: no matching audit event exists | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |
| Install hook (`postinstall` + `.ci-xxxxxx.sh`) instead of a workflow edit | MISSED: not a workflow change | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |

## Unverified
- That no undocumented audit action for workflow edits exists in real streams. I only checked the documented lists.
- Push webhook nested commit fields: the docs page lists `commits` but doesn't expand its objects in the copy I pulled.

## Tests / fixtures
None added. The query is unchanged and can't match documented events, so fixtures would only restate that. They'll be added with whichever option is chosen. Not run in local Splunk.

## Ponytail findings
- F1 (dead query): failing input: a GitHub audit event for a real workflow change. The only documented candidate is `git.push`, which the query doesn't select and which carries no file path. Fix: none applied; tagged needs-review (see Options).
- F2 (author): the author stays as-is while the repo-wide author cleanup is on hold.

## Reviewer status
pending human review (needs-review)
