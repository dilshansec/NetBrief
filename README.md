# NetSentry v0.1 — Local PCAP Analyzer

A locally hosted, extensible packet-capture analyzer for personal defensive-security study.

## Features

- Upload `.pcap`, `.pcapng` or `.cap` (max **25 MB**)
- Pure-Python, dependency-free **capture parsing** (no Wireshark/TShark required)
- Ethernet, VLAN, IPv4, IPv6, basic TCP/UDP/ICMP/ARP metadata; basic DNS port recognition
- Protocol breakdown, top source/destination IPs, top destination ports, minute traffic histogram
- First 500 packets in searchable table
- **Possible TCP SYN port scan** heuristic: 15+ distinct destination ports, same src/dst, within 60 sec where timestamps exist
- Export a JSON report; all data processed in memory and not persisted
- FastAPI backend and self-contained HTML/JS frontend
- Synthetic example capture with documentation-address ranges

## Quick start: Windows 10/11 (PowerShell)

Install **Python 3.10+** from https://www.python.org/downloads/ and enable "Add python.exe to PATH".

Extract the ZIP, open PowerShell in the `NetSentry-MVP` directory and execute:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m uvicorn netsentry.main:app --host 127.0.0.1 --port 8000
```

Then visit **http://127.0.0.1:8000**. Or double-click `start_windows.bat`.

If PowerShell activation is blocked, no changes are needed: commands above use the venv executable directly.

## Linux / macOS

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn netsentry.main:app --host 127.0.0.1 --port 8000
```

## Try the included sample

Click **Load sample capture**. It creates a medium-severity *possible SYN scan* alert from 25 artificial TCP SYN packets from `192.0.2.10` to 25 destination ports on `198.51.100.20`.

The sample is simulated, not captured from a real network. Or import your own capture (Wireshark > File > Save As).

## Run tests

```bash
.venv/Scripts/python.exe -m pip install pytest httpx  # Windows; use .venv/bin/python on Linux
.venv/Scripts/python.exe -m pytest -q
```

## API

- `GET /` — dashboard
- `GET /api/health` — health check
- `POST /api/analyze` — multipart `file` field, returns JSON summary
- `GET /sample` — synthetic demo capture
- `GET /api/docs` — interactive FastAPI docs

## Security and scope

**Local-only:** bind to `127.0.0.1`, not `0.0.0.0`, because this MVP lacks authentication, request throttling and process isolation. The server does not store uploaded captures or logs, though the browser holds analysis results until refreshed. JSON reports are saved only when the user explicitly exports one.

Metadata is **not** the same as full Wireshark decoding: no payload display, no TCP reassembly, no application-layer decoding, no live capture, no IDS signature matching. Heuristic alerts can be false positives and their absence does not establish safety.

PCAPNG support is focused on common section/interface/enhanced-packet blocks and link types Ethernet, Linux cooked v1 and raw IP. Other link-layer formats and advanced protocol dissectors are out of scope. Unsupported packets count under OTHER, and parsing records may be partial.

The 25-MB upload limit and 300,000-packet limit are safeguards, not a sandbox for hostile files. Parse only captures you own or have permission to inspect. Do not make this version internet-accessible.

## How to extend

- `netsentry/parser.py`: core parsing, stats, heuristic logic — refactor into pluggable `analyzers/` and `detectors/` packages as the feature set grows.
- `netsentry/main.py`: API endpoints — add routers for results, rules and history.
- `static/index.html`: dashboard — later swap for React without changing JSON API contracts.
- Add TShark for richer protocol decoding, Zeek for connection logs, Suricata for signatures, PostgreSQL for history, background workers for large files, and secure isolated workers before public deployment.

## Suggested v0.2 milestones

1. Separate scan detection into versioned rules with confidence scores and timestamps.
2. Add IPv4/IPv6 fragmentation-aware parsing, DNS query parser and packet search pagination.
3. Integrate optional TShark subprocess with strict resource bounds.
4. Add case management and local SQLite results history (opt-in, with retention/deletion settings).
