# REVIEW — DAC-CS-0239 Falcon Linux: PAM module written, built, or pam.d config edited

## Coverage before
New rule. No prior coverage of T1556.003 PAM module write/build/config on Linux Falcon in this repo.

## Coverage after
Four clean-room branches on `event_platform=Lin`:
1. `ELFFileWritten` of `.so` under documented PAM module directories (`/lib/security`, `/lib64/security`, `/usr/lib/security`, `/usr/lib64/security`, `/lib/x86_64-linux-gnu/security`, `/usr/lib/x86_64-linux-gnu/security`).
2. `ProcessRollup2` for `gcc`/`cc`/`clang`/`g++`/`ld` with `-shared` and a PAM path or Atomic-style `/tmp/pam_*.so` / `/dev/shm/*.so`.
3. `ProcessRollup2` for GTFOBins transfer/write binaries (excluding wget/curl) whose `CommandLine` references a PAM module path or `/etc/pam.d/`.
4. `ProcessRollup2` for `sed`/`tee`/`awk` editing `/etc/pam.d/`.

Package-manager and PAM-config-tool parents are allowlisted.

## ATT&CK mapping check (v19.2)
- T1556.003 Pluggable Authentication Modules — tactics on the technique page are Defense Impairment, Persistence, Credential Access. Mapped as `defense-impairment`, `persistence`, `credential-access`. Correct. https://attack.mitre.org/techniques/T1556/003/

## What the rule covers (exact)
- `.so` basename under the six PAM directories above via `ELFFileWritten.TargetFileName`.
- Compiler/linker command lines containing both `-shared` and a PAM/`/tmp/pam_`/`/dev/shm` `.so` path.
- Named writer/transfer binaries with a PAM path or `/etc/pam.d/` substring in `CommandLine`.
- `sed`/`tee`/`awk` with `/etc/pam.d/` in `CommandLine`.

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| Replace `pam_unix.so` in PAM dir (Skidmap) | T1556.003 | https://www.trendmicro.com/en_us/research/19/i/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload.html ; https://attack.mitre.org/techniques/T1556/003/ | yes if `ELFFileWritten` emits for that path (tenant unconfirmed) | low–med (pkg mgr) | added (A) | Core procedure; ParentBaseFileName allowlist for package managers |
| `cp … /usr/lib/security/` after build (zephrax) | T1556.003 | https://github.com/zephrax/linux-pam-backdoor | yes (ProcessRollup2 CommandLine) | med → tightened | tightened (C) | Require PAM path in CommandLine |
| `gcc -shared -fPIC -o /tmp/pam_evil.so` then pam.d insert | T1556.003 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.003/T1556.003.yaml | yes | med on build hosts → tightened | tightened (B+D) | Require `-shared` plus PAM or `/tmp/pam_`/`/dev/shm` path; sed branch for pam.d |
| `sed -i` insert auth rule into `/etc/pam.d/*` | T1556.003 | Atomic T1556.003.yaml | yes | med | added (D) | Exact Atomic pattern |
| `scp`/`sftp` drop `.so` into PAM dir | T1556.003 | https://gtfobins.github.io/gtfobins/scp/ ; https://gtfobins.github.io/gtfobins/sftp/ | yes | low if path-gated | added (C) | Path required |
| `openssl` download/file-write into PAM dir | T1556.003 | https://gtfobins.github.io/gtfobins/openssl/ | yes | low if path-gated | added (C) | |
| `socat` file-write/download into PAM dir | T1556.003 | https://gtfobins.github.io/gtfobins/socat/ | yes | low if path-gated | added (C) | |
| `nc`/`ncat` download into PAM dir | T1556.003 | https://gtfobins.github.io/gtfobins/nc/ | yes | low if path-gated | added (C) | |
| `tftp`/`ftp` download into PAM dir | T1556.003 | https://gtfobins.github.io/gtfobins/tftp/ ; https://gtfobins.github.io/gtfobins/ftp/ | yes | low if path-gated | added (C) | |
| `python`/`perl`/`ruby`/`php` write/download into PAM dir | T1556.003 | GTFOBins each | yes | med → tightened | tightened (C) | Path required; may FP on admin automation — not measured |
| `dd`/`tee`/`xxd` write into PAM path | T1556.003 | https://gtfobins.github.io/gtfobins/dd/ ; tee; xxd | yes | med | tightened (C/D) | Path required |
| `busybox` applet with PAM path in args | T1556.003 | https://gtfobins.github.io/gtfobins/busybox/ | yes | med | tightened (C) | Path required |
| `cp` from staging into PAM dir | T1556.003 | GTFOBins cp; zephrax README | yes | med–high without path → tightened | tightened (C) | Path required in CommandLine |
| wget/curl into PAM dir or PAM source tarball | T1556.003 | GTFOBins wget; Elastic PAM Source Download; zephrax uses wget | yes | low–med | dropped | Explicitly excluded from this rule; Elastic publishes a curl/wget PAM-source rule |
| `install` placing `.so` | T1556.003 | GTFOBins install = privilege-escalation only; Elastic excludes `/usr/bin/install` as FP | — | high | dropped | Legitimate package/install path |
| `base64`/`cat` via shell redirect | — | GTFOBins: file-read only | shell redirect is bash | high | dropped | No GTFOBins file-write |
| `rsync` into PAM dir | — | GTFOBins rsync: no file-download/file-write function listed | ProcessRollup2 possible | med | dropped | No accepted primary source for write/download function |
| `mv` into PAM dir | — | No GTFOBins page | ProcessRollup2 | med | dropped | No accepted primary source |
| Module *load* of malicious `.so` | T1556.003 | ATT&CK DET0454 / AN1250 | CS Linux module-load ESN not confirmed in public content opened | — | dropped | Not detectable with confirmed telemetry |
| `CriticalFileModified` on `/etc/pam.d` | T1556.003 | ESN name in FLTR Search-ThreatHunting.yaml | Linux pam.d emission unconfirmed | — | dropped | Use ProcessRollup2 sed/tee/awk instead |
| Renamed compiler / renamed `cp` | T1556.003 | common evasion | name-based ImageFileName miss | — | miss (accepted) | Path-based ELF write branch still catches the write if ESN fires |

## Unverified ideas
- Confirm `ELFFileWritten` fires for `.so` under `/usr/lib/security` (and siblings) in a real Linux Falcon tenant.
- Confirm `ParentBaseFileName`, `CommandLine`, `TargetFileName`, and `FileName` field names/population on Linux `ELFFileWritten` (ESN confirmed in public CS content; field population not measured).
- `CriticalFileModified` (or other non-ELF write ESN) for `/etc/pam.d/*` and `/etc/security/pam_*`.
- `ContextBaseFileName` as writer identity on Linux file events.
- aarch64 / other multiarch PAM directories (only Elastic + Debian default paths used).
- `rsync`, `mv` as writers once a primary source documents the capability for this use.
- Correlate Branch B `/tmp/pam_*.so` compile to a later Branch A/C write with `correlate()` (scheduled-search only).

## False-positive check
- Package managers / PAM tools: allowlisted from Elastic rule f48ecc44 false-positive list. https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_pluggable_authentication_module_creation.toml
- Noise overall: **not measured**.

## Tests
Tests added as synthetic data files under `tests/cases/DAC-CS-0239/`; no per-rule test runner exists in the repo (CI only runs `validate_repo.py`), so results are **not run**.

## Reviewer status: pending human approval
