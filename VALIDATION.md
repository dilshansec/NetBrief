# Validation — 2026-11-18

Verified on Windows / Python 3.12, in the existing virtual environment.

- `python -m pytest -q`: **48 passed**, **18 subtests passed**, 12.65 seconds in final run. One upstream Starlette warning advises migrating its test client from httpx to httpx2; it did not affect outcomes.
- `node tests/test_filters.cjs`: **12 assertions passed**.
- `node tests/test_reporting.cjs`: **18 assertions passed**, including identifier/token omission, nonmutation and CSV formula neutralization.
- `node --check static/app.js` and `node --check static/soc.js`: passed.
- `python -m pip_audit -r requirements.lock`: **no known vulnerabilities found** for the pinned installed runtime versions. Machine-readable details: dependency-audit.json. An advisory scan is not a security guarantee.

Python coverage includes PCAP/PCAPNG, invalid/truncated/empty captures, IPv6 ICMP, bounded packet rejection, HTTP metadata minimization, DNS compression-loop protection, existing TCP handshakes and exact interleaved frame references, all nine detector categories, normal traffic, threshold boundaries, SYN response visibility, beacon jitter, ordinary DNS names, allowlist annotation, per-analysis bearer isolation, pagination, cache capacity/expiry, rate/concurrency rejection, validation errors, file closure and worker timeout cleanup.

Browser checks at http://127.0.0.1:8000:

- Synthetic scan upload produced 30 packets / 30 flows / one scan finding.
- Finding expanded with real statistical evidence; status changed to Investigating.
- Evidence selection opened exactly 30 referenced packets; packet #1 showed decoded details and related finding.
- Existing conversation demo retained a 40 ms handshake and selected only frames #1–3.
- Graph rendered real hosts/flows; keyboard node selection opened its host profile.
- Report preview pseudonymized IPs; JSON download succeeded and was inspected: redacted filename, pseudonymized source, no access token.
- Comparing the conversation demo against scan showed 16→30 packets and 0→1 findings.
- Mobile 390×844 dashboard layout inspected; navigation scrolls horizontally and metrics use two columns.
- No browser error logs observed in the tested workflows.

During QA, corrected a stylesheet-order defect that let the navigation cover content. The final sidebar and content layout were rechecked.

Limits: automated tests use controlled fixtures, not a real-world detection benchmark. No full frontend browser automation suite, exhaustive button test, fuzz campaign, sustained load test, Docker build, hosted deployment, Linux memory-limit validation or print-to-PDF file verification was performed. Rule and product limitations are documented in README.md and DETECTION_RULES.md. These results do not establish production accuracy or security.

## Simplified workspace — 2026-11-19

- Two primary sections: Basic details and Suspicious activity; secondary tools are expandable.
- Communication grouping regression verifies repeated packets, reverse directions, different ports and protocols count as one IP pair.
- Python regression: 48 passed, 18 subtests passed (includes all nine synthetic detector categories). Existing upstream Starlette warning remains.
- JavaScript: communication grouping passed; 12 packet-filter and 18 reporting assertions passed.
- Headless Edge browser: two navigation entries; scan sample gives 2 IPs, 1 communication, 30 packets and one finding; evidence opens 30 packets; all nine coverage entries present; report renders; 390px mobile layout has no horizontal page overflow. No JavaScript errors.

## Single continuous page — 2026-11-19

Supersedes the two-view navigation described above. Basic details now precede suspicious findings on the same page. Removed the sidebar, packet explorer, packet filters, map, host drilldown and timeline UI. Finding evidence is displayed as frame references for Wireshark. The browser no longer downloads packet pages after analysis. Detector logic is unchanged.

JavaScript syntax checks passed. Headless Edge checks passed for summary/findings simultaneously visible in the correct order, absent packet filter/explorer elements, scan detection and evidence references, coverage, reports, 390px mobile width, repeat upload and normal-traffic empty state. No browser JavaScript errors.

## Unified lab sample and activity counts — 2026-11-19

Removed the separate demo button. The default mixed scenario uses Analyze lab capture. Synthetic traffic now produces 5 IP addresses, 3 unordered IP pairs, TCP/ARP/DNS/ICMP, 321 packets, 4 findings and 2 high-severity findings under default settings. No detector thresholds or displayed totals were hard-coded for the demo. Added detected distinct activity types / enabled activity types (4 / 9 by default), alongside evidence coverage.

Detection suite: 20 passed, 19 subtests passed, including exact mixed-sample counts and evidence. JavaScript syntax checks passed. Local headless Edge checks verified the single lab action, all requested metric values, activity counts, repeat upload, normal capture and no JavaScript errors. Inspected the desktop screenshot.

## GitHub update validation — 2026-11-19

Validated the prepared NetBrief checkout: 48 Python tests and 19 subtests passed; communication grouping and exact evidence ranges passed; 18 reporting/privacy and 12 legacy packet-filter assertions passed. One upstream Starlette/httpx deprecation warning remains. Latest browser checks also verified visible evidence ranges on collapsed findings. Only offline-generated sample captures are included.
