# REVIEW - DAC-VMW-0039 ESXi shell command decoded at runtime (awk decode or escape-sequence substitution)

## Attribution
Clean-room. Logic written from the attacker behaviour described in CrowdStrike's public blog "CrowdStrike Threat Hunts for Shell Command Obfuscation on VMware ESX" (Erez Goldberg, 7 Aug 2026): https://www.crowdstrike.com/en-us/blog/crowdstrike-hunts-for-shell-command-obfuscation-vmware-esx/ . CrowdStrike's CQL regexes were **not** copied; the patterns here are new and narrower. Attacker command samples from the blog are used as malicious fixtures and are cited in each fixture. No employer or client data was used.

## Telemetry
- Splunk Add-on for VMware ESXi Logs rewrites `vmw-syslog` to `vmware:esxlog:<app>`; ESXi shell.log lands as `vmware:esxlog:shell` (https://docs.splunk.com/Documentation/AddOns/released/VMWesxilogs/SourceTypes, https://docs.splunk.com/Documentation/AddOns/released/VMWesxilogs/Install).
- Both are already allowlisted (`vmw-syslog`, `vmware:esxlog*`); the allowlist was not edited. The query uses `sourcetype=vmw-syslog OR sourcetype=vmware:esxlog:shell` (no index=).
- Match field: `Message`, as in the existing ESXi rules (e.g. DAC-VMW-0018), with `_raw` as fallback via `coalesce`. Field name not checked against real data; `telemetry_validated: false`.
- The blog states shell.log records the command **before** expansion, which is why this works.

## ATT&CK v19.2 (checked on attack.mitre.org 2026-11-02)
- T1027 Obfuscated Files or Information - tactic Stealth
- T1140 Deobfuscate/Decode Files or Information - tactic Stealth
- T1059.004 Command and Scripting Interpreter: Unix Shell - tactic Execution
- Note: in v19.2 these show tactic "Stealth" (formerly Defense Evasion).

## Logic (any branch fires; `matched_pattern` shows which)
| Branch | Idea |
|---|---|
| awk_to_shell | awk output piped to `sh`/`bash`/`/bin/sh`/`busybox sh` |
| awk_system | awk calling `system(` |
| awk_bitwise | awk using `xor(`/`and(`/`or(`/`lshift(`/`rshift(`/`compl(` (BusyBox GNU math ext.) |
| awk_charcode | awk with `%c` and a 2-3 digit number on the same line |
| printf_escape_subst | `$(printf` or `` `printf `` followed by **3+ consecutive** `\xHH` / `\NNN` escapes |
| ansi_c_escape | `$'` followed by **3+ consecutive** `\xHH` / `\NNN` escapes |
Literal backslash is written as `\x5c` in the SPL regex to avoid SPL string-escape ambiguity.

## Ponytail review
| # | Sev | Finding | Failing input | Fix |
|---|---|---|---|---|
| 1 | Must | A lone `\xHH` / `\NNN` (as in the blog's broad pattern) appears in admin printf lines | `printf "line\x0a"` | Require 3+ consecutive escapes **and** a command substitution / ANSI-C quote |
| 2 | Must | `awk` alone is everywhere in admin scripts | `awk '{print $3}'` | awk only fires with shell pipe, system(), bitwise funcs or %c+number |
| 3 | Should | Morse/binary/scientific decoders have no numeric escapes | Morse sample | Caught by awk_to_shell branch |
| 4 | Should | `| sh` regex could hit `| shasum`/`| shell` words | `... | grep -v shell` | sh must end at whitespace, `;`, `)` or end of line |

## Dropped / not covered (known gaps, fixtures labelled known-gap)
- Broad blog patterns: `${VAR}${VAR}`, short `$a$b$c`, `awk substr ... print`, single octal/hex escape, `eval`/`sh -c` with variable. Dropped as noisy; the blog published no FP counts for them.
- Environment-variable character extraction (`$(echo $TERM | cut -c 3)...`), sed capture-group reversal, `python -c chr()`, od+awk reversal inside `$( )`, and octal printf written to a file then `sh $F`. Not caught. The last is caught by DAC-VMW-0040 when logger -t vmkernel is used.
- Multi-line commands: the blog shows some samples wrapped; fixtures flatten them to one line. Whether shell.log keeps them on one event is unverified.

## Fixtures
`tests/cases/DAC-VMW-0039/` - 12 malicious, 5 benign (blog baseline table), 5 near-miss, 5 known-gap. All `synthetic: true`, `result: not run`. Regex logic was checked locally in Python only; no Splunk run.

## Open questions
- Confirm `Message` is extracted for `vmware:esxlog:shell` in the target Splunk (ESXi 7/8 shell.log format `shell[pid]: [user]: <cmd>`).
- Rule severity high pending real noise data.
