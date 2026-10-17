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
