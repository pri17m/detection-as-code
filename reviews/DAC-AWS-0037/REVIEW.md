# REVIEW - DAC-AWS-0037 AWS: IAM UpdateAssumeRolePolicy broaden trust

## Attribution
Fix driven by Aikido Security, "Compromised GitHub accounts push CI secret stealer to tens of thousands of repositories" (Oliver Smith, 12 Nov 2026): https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories. Aikido says the payload "sets the chained role's trust policy to `"Principal": {"AWS": "*"}`, which opens the role to any AWS account." Aikido published no query; the SPL is our own, from the AWS IAM and CloudTrail docs. No employer, client or tenant data. Fixtures are synthetic.

## As-is
Title and description say UpdateAssumeRolePolicy with Principal=*, but the query was:
`search eventSource="sts.amazonaws.com" eventName="AssumeRole" | search requestParameters.roleArn="*admin*" ...`
That is the same search as DAC-AWS-0009. It never looked at `UpdateAssumeRolePolicy`, so it could not fire on a trust change, and it fired on every AssumeRole into a role with "admin" in its name. Replayed against the new fixtures: all three malicious cases 0 rows (FAIL), and the benign AssumeRole into `AdminRole` 1 row (FAIL).

## After
Successful `iam:UpdateAssumeRolePolicy`. The new `requestParameters.policyDocument` is parsed (Statement as an array or a single object). For each `Allow` statement with an AWS principal it reports:
- `any_aws_principal`: `Principal` is `"*"` or `Principal.AWS` contains `"*"`, and the statement has no `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:PrincipalAccount`, `aws:PrincipalArn` or `aws:SourceAccount` condition.
- `foreign_account`: `Principal.AWS` names an account ID other than `recipientAccountId`.

Severity is critical for `any_aws_principal` or when the caller is a GitHub OIDC session (`webIdFederationData` from `token.actions.githubusercontent.com`), otherwise high.

New rule idea 1 from the Aikido research ("trust policy opened to any AWS principal") is folded into this rule instead of becoming a separate rule. It is exactly what this rule's title promised, and a second rule on the same event would duplicate alerts.

CloudTrail logs only the new policy, not the old one, so "broaden" here means the new policy is open, not a measured diff. `telemetry_validated: false`.

## ATT&CK v19.2
T1098.003 (persistence, privilege-escalation), T1484.002 (privilege-escalation, defense-impairment). Checked against enterprise-attack-19.2.json from mitre-attack/attack-stix-data: both present, not revoked or deprecated; tactics taken from kill_chain_phases.

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| `"AWS": "*"` plus a junk condition on an org key, e.g. `aws:PrincipalOrgID` set to an org the attacker controls | MISSED: any of the scoped keys suppresses the wildcard branch; the value is not checked | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html |
| Trust to a single attacker-owned account instead of `*` | Caught as `foreign_account` (high) | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| New role created with an open trust (`CreateRole`) instead of updating one | MISSED here; DAC-AWS-0024 looks at CreateRole with external principals | https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html |
| Federated principal (attacker OIDC provider) instead of an AWS principal | MISSED: only `Principal.AWS` and `Principal: "*"` are checked | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| Principal given as an account ARN in another partition (aws-cn, aws-us-gov) | Caught: the account regex allows `arn:aws[a-z-]*` | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html |

## Unverified
- That CloudTrail stores `requestParameters.policyDocument` as plain JSON text for UpdateAssumeRolePolicy in every pipeline. The Stratus Red Team detonation log shows it plain; some forwarders URL-encode policy documents, which would break `spath`.
- Whether `webIdFederationData` stays on a session after a second AssumeRole hop. If it doesn't, chained CI sessions get high instead of critical.
- No volume data for `foreign_account` in real accounts.

## Tests / fixtures
`tests/cases/DAC-AWS-0037/`: all synthetic (`"synthetic": true`). Account IDs are AWS example values and IPs are RFC 5737 documentation ranges, not indicators.

Splunk Enterprise 9.4.1 (throwaway local instance on the agent box). No Splunk add-ons installed, so a local props.conf set `KV_MODE = json` for the sourcetype (`aws:cloudtrail` timestamps from `eventTime`, `github:audit` timestamps from `@timestamp` in epoch ms). Field names are the raw JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -index dac`, and the rule query ran unchanged via REST (`search index=dac source="<fixture>" <query>`, earliest=0). The events are synthetic, so this shows the SPL parses and the logic does what each fixture says. It says nothing about real volume or real field shapes. CI does not run fixtures (the repo has no Splunk runner).

| Fixture | Label | Expect alert | Rows | Result | Rows with the as-is query | What it is |
|---|---|---|---|---|---|---|
| malicious_0_synthetic.json | malicious | True | 1 | PASS | 0 | Chained CI role session sets trust to `Principal.AWS *`, no condition (critical) |
| malicious_1_synthetic.json | malicious | True | 1 | PASS | 0 | Single Statement object with `Principal: "*"` |
| malicious_2_synthetic.json | malicious | True | 1 | PASS | 0 | Foreign account root added to a `Principal.AWS` list (high) |
| benign_3_synthetic.json | benign | False | 0 | PASS | 1 | Same-account role plus a service principal; also an AssumeRole into `AdminRole` |
| near_miss_4_synthetic.json | near_miss | False | 0 | PASS | 0 | `AWS *` scoped by `aws:PrincipalOrgID`; a failed (AccessDenied) wildcard update |

## Ponytail findings
Ponytail pass (2026-11-12): correctness, safety, behaviour under load, tests, speed, every line needed. Each finding was replayed in local Splunk against a draft without the fix.

- F1 (wrong event): failing input: `malicious_0..2` returned 0 rows and `benign_3` returned 1 row with the as-is query. Fix: rewrote the query on `iam.amazonaws.com` / `UpdateAssumeRolePolicy`.
- F2 (single Statement object): failing input: `malicious_1_synthetic.json`. A draft that read only `Statement{}` returned 0 rows, because IAM allows `Statement` to be one object. Fix: `stmt=if(isnotnull(stmt_list), stmt_list, stmt_one)`. Replay: 1 row.
- F3 (failed calls): failing input: `near_miss_4_synthetic.json`. A draft without the errorCode filter alerted on an AccessDenied update that changed nothing. Fix: `where isnull(errorCode)`. Replay: 0 rows.
- F4 (org-scoped wildcard): failing input: `near_miss_4_synthetic.json`. A draft that alerted on every `AWS *` flagged the documented `aws:PrincipalOrgID` pattern. Fix: `scoped_condition` suppresses the wildcard branch for the org, account, ARN and source-account keys. Replay: 0 rows. The bypass this opens is listed above.
- F5 (author): the rule's author stays "Detection Engineer". Changing it is part of the repo-wide author cleanup that's on hold.

## Reviewer status
pending human review
