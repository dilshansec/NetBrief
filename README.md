# NetBrief 0.3 — Network Investigation

A local-first, evidence-led PCAP investigation workspace for a SOC student portfolio. Retains the original FastAPI, pure-Python parser and buildless JavaScript architecture. It analyzes **recorded captures only**; it never scans, transmits captured packets, executes extracted content or contacts captured addresses.

The application and Python package use the NetSentry name. This is the updated implementation of the NetBrief repository.

## Run locally (Windows)

Clone [dilshansec/NetBrief](https://github.com/dilshansec/NetBrief) and open its folder before running the commands below.

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.lock
.venv\Scripts\python.exe -m uvicorn netsentry.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. `start_windows.bat` performs setup and starts the app. Python 3.10+; tested with Python 3.12. No Node build, database, TShark, Scapy or external frontend CDN is needed.

On Linux/macOS substitute `.venv/bin/python` for `.venv\Scripts\python.exe`. Settings in `.env.example` are examples: export them into the process environment; the application does not automatically load a `.env` file.

## What is implemented

- PCAP/PCAPNG, Ethernet/VLAN, raw IP and Linux cooked v1; IPv4/IPv6, TCP/UDP, ICMP/ICMPv6, Ethernet ARP mappings. Bounded DNS question/response metadata, HTTP method/status and TLS record metadata.
- Nine independently configurable heuristic detection categories with exact frame evidence, flows, statistical indicators, confidence, impact, benign explanations, limitations and investigation steps.
- One continuous page: compact **Basic details** first (unique IPs, bidirectional IP-pair communications, protocols, packet count, duration and bytes), followed immediately by **Suspicious activity**. A communication counts an IP pair once across ports and protocols.
- Findings include exact evidence frame numbers for reviewing the original capture in Wireshark. No in-app packet explorer or packet filters.
- Severity/confidence/category/address filtering, analyst statuses, source/time-based incident groupings, priority findings and comparison against the previous capture.
- JSON/CSV exports and browser printing (save PDF), with identifier pseudonymization enabled by default.
- Eleven synthetic lab scenarios (including a four-activity demo) generated offline and analyzed through the real engine.
- Signature/extension validation, 10 MB upload / 50,000 packet defaults, one analysis at a time, 45-second disposable-worker timeout, global 20-uploads/minute rate limit, expiring bearer-protected reports, bounded request body and closed upload spools.

## Suggested workflow

1. Under **Upload or change capture**, upload a capture or expand **Try a sample capture**.
2. Review coverage and priority findings under **Suspicious activity**. No alerts does **not** guarantee safety.
3. Expand a **Suspicious activity** finding, read its evidence and alternatives, and review referenced frames in Wireshark if needed.
4. Review severity, confidence, source/destination addresses and investigation steps. Analyst statuses are browser-memory only.
5. Review pseudonymized **Reports**, download JSON/CSV or print to PDF.
6. Change **Detection settings**, then analyze again. Settings never retroactively change existing results. Trusted hosts/scanners/domains annotate findings rather than hiding them.

## Tests

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest -q
node tests/test_filters.cjs
node tests/test_reporting.cjs
.venv\Scripts\python.exe -m pip_audit -r requirements.lock
```

See [VALIDATION.md](VALIDATION.md) for verified results and [DETECTION_RULES.md](DETECTION_RULES.md) for thresholds and limitations. Synthetic tests validate implementation behavior, not production detection accuracy.

## Structure

```text
netsentry/
  main.py              API, access tokens, limits and retention
  worker.py            Disposable analysis process
  parser.py            PCAP/PCAPNG and network-layer decoder
  metadata.py          Bounded application metadata
  connections.py       Original TCP handshake/data/close evidence
  config.py            Validated per-analysis policy
  investigation.py     Hosts, flows and evidence correlation
  detectors/
    __init__.py        Evidence envelope and coverage
    rules.py           Nine independent detector functions
static/
  index.html           Single-page summary and findings shell
  app.js, overview.js  Upload handling and IP-pair summary
  soc.js, soc.css      Investigation views and design system
  reporting.js         Shared redaction and CSV export helpers
samples/               Existing captures and offline lab generator
tests/                 Parser, rule, API and filter regression tests
```

## Scope and remaining work

This is a **local demonstration release, not a production IDS**. See [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md), [API.md](API.md), [DEPLOYMENT.md](DEPLOYMENT.md), [CONTRIBUTING.md](CONTRIBUTING.md) and [samples/README.md](samples/README.md).

Not implemented: TCP/application reassembly, TLS SNI/certificates/decryption, full DNS answer decoding, raw hex retention, trained baselines, rolling-window detections, persisted analyst cases, live job-progress percentages, independent capture comparison storage, external threat intelligence or production multi-user authentication. The frontend uses the summary response without downloading packet pages; paginated packet metadata remains available through the API. Windows has no enforced worker memory cap. Public deployment still requires operational hardening and owner approval.

No software license was added; the owner must choose one before presenting this as a licensed open-source release.
