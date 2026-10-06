---
name: detection-git
description: Commit and push a detection change on this repo without secrets. Use when committing a DAC rule fix, opening a pull request, or pushing lab/windows-eventlog.
---

# Git for this repo

Remote is `https://github.com/pri17m/detection-as-code`. Detection lab work is on `lab/windows-eventlog`. Do not commit on `main` unless asked.

## Commit

- One concern per commit. A query fix and a skill file are different commits if both are requested.
- Subject style already in the branch: `fix(splunk): ...` or `feat(schema): ...`.
- Do not stage `C:\lab\`, `secrets\`, password files, review JSON that still has the account name, or `.env`.
- Do not set git config. If a commit needs an author, use the existing repo author only when the user asked you to commit as them.
- Do not commit `telemetry_validated: true` unless `detection-reality-checker` passed and `sample-redaction` was applied.

## Push

- Push only when the user asked.
- Push `lab/windows-eventlog` to `origin`. Do not force-push.
- Do not merge the pull request unless the user said to merge.
- After a push, give the commit hash and the path. Do not paste file contents that contain a secret.
