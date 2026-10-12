# REVIEW — DAC-CS-0204 Smash-and-grab privileged group add correlated with DCSync tooling

## Coverage before
UserAccountAddedToGroup with GroupRid decoded to 512/519/544 correlated (selfJoinFilter on aid) with later ProcessRollup2 matching secretsdump|lsadump::dcsync|ntdsutil.*ifm|--just-dc or matching images.

## Coverage after
Same, plus `Get-ADReplAccount` in tooling regex; technique list adds T1098.007 (Additional Local or Domain Groups) alongside T1098.

## ATT&CK mapping check (v19.2)
- T1098 Account Manipulation — Persistence, Privilege Escalation. Correct parent. https://attack.mitre.org/techniques/T1098/
- T1098.007 Additional Local or Domain Groups — more precise sub-technique for RID 512/519/544 adds. Added. https://attack.mitre.org/techniques/T1098/007/
- T1003.006 — correct for stage 2.

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| Get-ADReplAccount as stage-2 | T1003.006 | Atomic T1003.006 a0bced08 | yes | low | added | Same as 0201/0203. |
| Rapid remove after dump (UserAccountRemovedFromGroup) | T1098.007 | Rule description (unconfirmed) | unconfirmed | n/a | dropped | Rule already documents the event as unconfirmed in tenant; no public schema opened confirming the ESN. |
| Add to other privileged groups (e.g. Backup Operators RID 551) | T1098.007 | https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids | yes | medium | dropped | Expanding RIDs without tenant baselining raises FP from legit ops; keep 512/519/544. |

## Unverified ideas
- Confirm parseInt(GroupRid, radix=16, endian=big) on real Falcon events (already noted in rule description).

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.

## Reviewer status: pending human approval
