# Third-Party Notices

## ByteRay-Labs Query-Hub

- Upstream: https://github.com/ByteRay-Labs/Query-Hub
- Used for: 86 CrowdStrike detections in `detections/` whose `references` link to Query-Hub query files. Each of those rules carries an attribution line in `references` pointing to this notice.
- License: MIT, as stated in the upstream README (https://github.com/ByteRay-Labs/Query-Hub/blob/main/readme.md), section "License":

  > Released under the **MIT License**. All queries are free to use, share and adapt — attribution is appreciated.

- Note: the upstream repository has no LICENSE file (checked 2026-10-12). The README line above is its only license statement.
- Copyright holder: the upstream README names none, so the notice below uses "ByteRay-Labs contributors". No year is stated upstream, so none is given.

### MIT License (text from https://opensource.org/license/mit)

Copyright (c) ByteRay-Labs contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## detections.ai community rules

- Upstream: https://detections.ai
- Used for: behavioural detection topics and query structure in DAC-CS-0240..0243, DAC-MDE-0089..0093, DAC-WIN-0361. Each of those rules carries the detections.ai rule URL in `references` and an attribution line in the description and REVIEW.md.
- License: none shown on the individual rule pages (checked 2026-10-13). The site Terms of Service apply: https://detections.ai/terms/full (System Two Security Inc.). Those terms grant a limited right to access and use the Platform to view, share and generate detections; they prohibit modifying or creating derivative works of Platform elements and renting/distributing/selling rights to use the Platform. Copyright in community-posted rules rests with each contributor (or with System Two for Platform Materials). No open-source licence was displayed on the rule pages.
- Attribution authors as shown on the rule pages at capture time: Fatima Suvaid (@arhaminafs), Adarsh Pandey (@Pandeyadarsh), Arnold Chan (@slaz); some pages showed Unknown.
- Debarshi Ghosh (repo owner) explicitly directed that these rules be based on the detections.ai queries after being informed of the site terms. This notice records that choice and the missing per-rule licence.

## Stratus Red Team (DataDog)

- Upstream: https://github.com/DataDog/stratus-red-team
- Used for: attack technique definitions that test fixtures and references in DAC-AWS-0062..0069 are based on (technique pages linked in each rule's `references`).
- License: Apache-2.0, per the upstream LICENSE file (https://github.com/DataDog/stratus-red-team/blob/main/LICENSE, checked 2026-10-20).
- Upstream NOTICE (https://github.com/DataDog/stratus-red-team/blob/main/NOTICE), reproduced as Apache-2.0 section 4(d) requires:

  > Stratus Red Team
  > Copyright 2021-Present Datadog, Inc.
  >
  > This product includes software developed at Datadog (https://www.datadoghq.com/).

- Full licence text: https://www.apache.org/licenses/LICENSE-2.0

## splunk/attack_data

- Upstream: https://github.com/splunk/attack_data
- Used for: sample log lines that test fixtures under `tests/cases/` are taken from or derived from (edited copies are marked `_derived` and documented in each REVIEW.md) for DAC-AWS-0062..0069, DAC-OKTA-0011, DAC-PAN-0001, DAC-VMW-0015, DAC-VMW-0038. Source dataset URLs are in each rule's `references` and REVIEW.md.
- License: Apache-2.0, per the upstream LICENSE file (https://github.com/splunk/attack_data/blob/master/LICENSE, checked 2026-10-20). No NOTICE file upstream.
- Modified files: fixtures named `*_derived.json` were changed from the upstream lines; the changes are listed per fixture in the rule's REVIEW.md.
- Full licence text: https://www.apache.org/licenses/LICENSE-2.0

## Palo Alto Networks Splunk-Apps

- Upstream: https://github.com/PaloAltoNetworks/Splunk-Apps (sample files pinned at commit ae653b335e633895c1dcc796139d0c21c4c34696)
- Used for: sample log lines and sourcetype/field definitions behind DAC-PAN-0001 test fixtures; cited in the REVIEW.md of DAC-VMW-0015 and DAC-VMW-0038.
- License: ISC, per the upstream LICENSE file (https://github.com/PaloAltoNetworks/Splunk-Apps/blob/develop/LICENSE, checked 2026-10-20).

### ISC License (copyright line as stated upstream)

Copyright (c) 2013-2020, Palo Alto Networks Inc.

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

## Broadcom knowledge base (VMware ESXi)

- Upstream: https://knowledge.broadcom.com/external/article/318905, /320681, /438753 (and other KB articles linked in DAC-VMW-0027..0038 `references`).
- Used for: short ESXi log-line formats cited as references for DAC-VMW rules.
- License: none claimed. These are cited as references only; no licence beyond citation is asserted, and Broadcom's site terms apply to the articles themselves.

## 0x4D31/honeypot-data (PHP2Shell confirmed-RCE evidence)

- Upstream: https://github.com/0x4D31/honeypot-data (repository owner 0x4D31; content used at commit 0b6a57491134c10f7cc5055999f1cb8b38c67546)
- Report: https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md
- Evidence dataset: https://github.com/0x4D31/honeypot-data/tree/main/reports/php2shell/2026-10-24-rce-evidence
- Used for: Tetragon `process_exec` records from the 35 published cases (A01-A03, B01-B32), field-mapped into test fixtures named `*honeypot*_derived.json` under `tests/cases/` for DAC-CS-0245, DAC-MDE-0096 and DAC-WIN-0365, and the per-case command analysis in those rules' REVIEW.md files. Each of those rules links the report and dataset in `references`.
- License: Creative Commons Attribution 4.0 International (CC-BY-4.0), per the upstream LICENSE file (https://github.com/0x4D31/honeypot-data/blob/main/LICENSE, checked 2026-10-26).
- Changes made here: records were reshaped into each platform's field names (mapping stated in every fixture's `field_mapping`), the `UserName`/`AccountName` value `www-data` was derived from uid 33, and kprobe socket records were left out. Command lines, timestamps, node names, exec IDs and source IPs are as published. Upstream already replaced honeypot addresses with TEST-NET aliases (see the dataset README). These fixtures are not native EDR or SIEM telemetry and have not been run.
- Full licence text: https://creativecommons.org/licenses/by/4.0/legalcode
