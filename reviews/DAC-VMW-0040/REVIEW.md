# REVIEW - DAC-VMW-0040 ESXi shell runs logger with a spoofed vmkernel tag

## Attribution
Clean-room. Written from the "VMFS + Syslog combined steganography" technique in CrowdStrike's public blog "CrowdStrike Threat Hunts for Shell Command Obfuscation on VMware ESX" (7 Aug 2026): https://www.crowdstrike.com/en-us/blog/crowdstrike-hunts-for-shell-command-obfuscation-vmware-esx/ . The blog publishes no query for this behaviour; the logic is our own. The blog sample is used as a malicious fixture with citation. No employer or client data used.

## Telemetry
- ESXi shell.log via Splunk Add-on for VMware ESXi Logs: `vmware:esxlog:shell` (rewritten from `vmw-syslog`), https://docs.splunk.com/Documentation/AddOns/released/VMWesxilogs/SourceTypes . Both allowlisted already; allowlist not edited; no index=.
- Field `Message` (as in existing ESXi rules), `_raw` fallback. Unverified on real data; `telemetry_validated: false`.
- Note: the spoofed message itself would be re-typed by the add-on as `vmware:esxlog:vmkernel`, which is why this rule keys on the **shell command** that wrote it, not the fake entry.

## ATT&CK v19.2 (checked on attack.mitre.org 2026-11-02)
- T1036 Masquerading - tactic Stealth (spoofed vmkernel source tag). Chosen over T1027/T1140, which describe encoding, not log forgery.
- T1059.004 Unix Shell - tactic Execution.
- Open question: whether Debarshi prefers T1027 kept as well because the blog groups this under obfuscation.

## Logic
`logger` followed by `-t vmkernel`, combined short flags ending in t (`-st`), or `--tag=vmkernel` / `--tag vmkernel`, optional quotes, word boundary after `vmkernel` (so `vmkernelcheck` does not match).

## Ponytail review
| # | Sev | Finding | Failing input | Fix |
|---|---|---|---|---|
| 1 | Must | Matching `vmkernel` anywhere fires on messages that mention vmkernel.log | `logger -t healthcheck "checked vmkernel.log"` | Require it as the tag value |
| 2 | Should | Long and combined option forms | `logger --tag=vmkernel`, `logger -st vmkernel` | Covered |
| 3 | Should | Prefix tags | `-t vmkernelcheck` | Word boundary |

## Dropped / unverified
- Correlation with `sh` of a hidden `.sys*` file under `/vmfs/volumes` and `rm -f` in the same session: **not implemented**. ESXi shell.log entries carry no reliable session id in the documented add-on fields, and the blog sample is one compound line. A `transaction`/`streamstats` per host+user window could be added later once real shell.log events confirm the fields. Left unverified.
- Spoofing other daemon tags (hostd, vpxa, vobd): not included; open question.
- Tag held in a variable, or raw syslog via `nc`: known gaps (fixtures).

## Fixtures
`tests/cases/DAC-VMW-0040/` - 6 malicious, 2 benign, 3 near-miss, 2 known-gap. All synthetic, `result: not run`. Regex checked locally in Python only.
