# REVIEW — DAC-CS-0239 Falcon Linux: PAM module written, built, or pam.d config edited

## Coverage before
New rule. No prior coverage of T1556.003 PAM module write/build/config on Linux Falcon in this repo.

## Coverage after
Four clean-room branches on `event_platform=Lin`:
1. `ELFFileWritten` of `.so` under documented PAM module directories (`/lib/security`, `/lib64/security`, `/usr/lib/security`, `/usr/lib64/security`, `/lib/x86_64-linux-gnu/security`, `/usr/lib/x86_64-linux-gnu/security`).
2. `ProcessRollup2` for `gcc`/`cc`/`clang`/`g++`/`ld` with `-shared` and a PAM path or Atomic-style `/tmp/pam_*.so` / `/dev/shm/*.so`.
3. `ProcessRollup2` for GTFOBins transfer/write binaries (excluding wget/curl; interpreters match versioned names such as `python3.11`, `perl5.36`) where a PAM module path or `/etc/pam.d/` is the **destination**: the last argument, after `of=`/`-o`/`-O`/`-out`/`>`/`>>`, or inside a write-mode `open("...","w|a...")` / `file_put_contents("...")`.
4. `ProcessRollup2` for `sed`/`awk` editing `/etc/pam.d/` (`tee` is covered by branch 3).

The package-manager / PAM-config-tool allowlist is applied to `ParentBaseFileName`, to `ContextBaseFileName` (writing process on file events; field used on `*FileWritten` in CrowdStrike's public RMMHunting.yaml, https://github.com/CrowdStrike/logscale-community-content/blob/main/Misc/crwd_live_rmm/RMMHunting.yaml , population on Linux `ELFFileWritten` unconfirmed), and to the process's own `ImageFileName`. `NOT field=/re/` is used so a missing field does not drop the event.

## ATT&CK mapping check (v19.2)
- T1556.003 Pluggable Authentication Modules — tactics on the technique page are Defense Impairment, Persistence, Credential Access. Mapped as `defense-impairment`, `persistence`, `credential-access`. Correct. https://attack.mitre.org/techniques/T1556/003/

## What the rule covers (exact)
- `.so` basename under the six PAM directories above via `ELFFileWritten.TargetFileName`.
- Compiler/linker command lines containing both `-shared` and a PAM/`/tmp/pam_`/`/dev/shm` `.so` path.
- Named writer/transfer binaries with a PAM path or `/etc/pam.d/` substring in `CommandLine`.
- `sed`/`tee`/`awk` with `/etc/pam.d/` in `CommandLine`.

## Ponytail review fixes (2026-10-13)
| # | change | why |
|---|---|---|
| 1 | Allowlist also on writer (`ContextBaseFileName`) and `ImageFileName` | `sudo dnf update pam`: writer dnf, parent sudo previously alerted |
| 3 | Branch C requires PAM path as destination | `cp /etc/pam.d/sshd /root/bak` (a read) previously alerted |
| 4 | `python[0-9.]*`, `perl[0-9.]*`, `ruby[0-9.]*`, `php[0-9.]*` | `/usr/bin/python3.11` previously missed |
| 8 | `tee` removed from branch D | duplicate of branch C |
| 9 | RMMHunting.yaml removed from rule references | not a PAM source (kept here only as the field-name source for ContextBaseFileName) |
| — | ATT&CK tactic check | v19.2 STIX `enterprise-attack-19.2.json`: T1556.003 kill_chain_phases = defense-impairment, persistence, credential-access (https://github.com/mitre-attack/attack-stix-data/blob/v19.2/enterprise-attack/enterprise-attack-19.2.json). Unchanged. |

### Destination-matching limits (known misses)
- Interpreter writes where the path is built in code (variables, concatenation, `os.path.join`), Perl `open(FH, ">$p")`, Ruby `File.write`, here-docs, or `python script.py` with the path inside the script.
- Shell redirection (`cat x > /lib/security/...`) is done by the shell, so `ProcessRollup2` of the writer has no path; branch A (`ELFFileWritten`) is the fallback.
- Tools with the destination before other trailing args (`scp dst` patterns with extra flags after the path, `cp -t /lib/security/ x.so`). `cp -t` is a miss.
- Branch A still covers any `.so` written into the PAM dirs regardless of tool, if the ESN fires.

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
Added in ponytail fix: `benign_sudo_dnf_writer.json`, `near_miss_cp_read_pam_d.json`, `malicious_python311_write_pam_dir.json`.
Tests added as synthetic data files under `tests/cases/DAC-CS-0239/`; no per-rule test runner exists in the repo (CI only runs `validate_repo.py`), so results are **not run**.

## Reviewer status: pending human approval
