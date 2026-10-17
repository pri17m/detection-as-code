# REVIEW — DAC-MDE-0089 Node/Bun → api.github.com and registry.npmjs.org (same process)

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a130ac-86a8-7113-bc06-13f2c89caa15 by Adarsh Pandey (@Pandeyadarsh). No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## ATT&CK v19.2
- T1071.001 Web Protocols — command-and-control
- T1102 Web Service — command-and-control
- T1195.002 Compromise Software Supply Chain — initial-access

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Should | Source scanned `ago(7d)` then joined — heavy for a scheduled detection | Busy estate, 7d DeviceNetworkEvents | Lookback reduced to 1d; 30m pair window kept |
| 2 | Should | Source excluded npm strings in CommandLine but not npm/yarn/pnpm as parent | `node.exe` child of `npm.cmd` during install still pairs if cmdline lacks those tokens | Exclude InitiatingProcessParentFileName npm/yarn/pnpm |
| 3 | Nice | `hint.shufflekey` may be unsupported | — | Removed non-essential join hint |

## Field verification
| Field | Status | Source |
|---|---|---|
| DeviceNetworkEvents, RemoteUrl, InitiatingProcess* | verified | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |

## Public behaviour source
Endor Labs Tensorlake/Shai-Hulud write-up names api.github.com and registry.npmjs.org as worm network targets.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0089/; result: not run.
