# NetBrief

**Turn Wireshark capture files into clear network traffic summaries.**

NetBrief is a local web application that analyzes uploaded PCAP and PCAPNG files. It summarizes network activity, visualizes protocol usage, and highlights possible TCP SYN scan activity to support security investigations.

Built as a personal cybersecurity project for learning network analysis and digital forensics. **Current version: v0.1 MVP.**

## What you can do

- Upload `.pcap`, `.pcapng`, or `.cap` files up to **25 MiB**.
- Review packet counts, traffic volume, capture duration, and source IP counts.
- Explore protocol distribution, top source IPs, and destination ports.
- View packet activity on a minute-by-minute timeline.
- Search the first **500 packets** by IP, protocol, port, or packet number.
- Review possible TCP SYN scan indicators.
- Download the analysis as a **JSON report**.
- Try a bundled synthetic capture without uploading your own file.

## How it works

**Wireshark capture → Upload → Analysis → Dashboard → JSON report**

Save a capture in Wireshark, upload it to NetBrief, and review the results in your browser. NetBrief runs on your computer and does not require Wireshark or TShark to be installed.

## Getting started

You need **Python 3.10 or later**. Download this repository as a ZIP and extract it, or clone it:

```bash
git clone https://github.com/dilshansec/NetBrief.git
cd NetBrief
```

### Windows

Open PowerShell in the project folder and run:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m uvicorn netsentry.main:app --host 127.0.0.1 --port 8000
```

Alternatively, double-click **`start_windows.bat`** to set up and start the application.

### Linux / macOS

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn netsentry.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** in your browser. Click **Load sample capture** for a demo, or select your capture and click **Analyze capture**. Press `Ctrl+C` in the terminal to stop the server.

The internal Python package is still named `netsentry`, so the startup commands use `netsentry.main:app`.

## Technology and structure

- **Backend:** Python, FastAPI, Uvicorn
- **Frontend:** HTML, CSS, JavaScript
- **Capture parser:** Python standard library

```text
NetBrief/
├── netsentry/
│   ├── main.py          # API and dashboard delivery
│   └── parser.py        # Capture parsing, statistics, scan heuristic
├── static/index.html   # Dashboard and packet explorer
├── samples/            # Synthetic capture and generator
├── tests/test_app.py   # Parser and API tests
├── requirements.txt
└── start_windows.bat
```

## Tests and API

With the virtual environment created, run these commands on Windows:

```powershell
.venv\Scripts\python.exe -m pip install pytest httpx
.venv\Scripts\python.exe -m pytest -q
```

On Linux/macOS, replace `.venv\Scripts\python.exe` with `.venv/bin/python`.

Interactive API documentation is available at **http://127.0.0.1:8000/api/docs** while the server is running.

## Current limitations

- This version is intended for **local use**. Keep it bound to `127.0.0.1`; it has no authentication or request throttling.
- Parsing covers basic metadata and common capture formats. It does not provide full Wireshark decoding, payload inspection, TCP reassembly, or live capture.
- DNS recognition is based on UDP port 53; DNS queries are not decoded.
- SYN scan detection is experimental. It checks for 15 or more distinct destination ports per source/destination pair over the pair's full observed interval of up to 60 seconds, or without a time check if timestamps are missing. It does not use a rolling window and can miss scan bursts.
- Indicators require investigation: they do not prove an attack or successful compromise. No indicators does not mean a capture is safe.
- Processing is limited to **300,000 packets**. Reports include at most 500 packet rows, 500 populated timeline buckets, and 100 indicators.
- NetBrief does not maintain a capture history, but uploads may use temporary disk storage. Exported reports can contain sensitive network metadata.

## Next steps

Planned improvements include stronger capture validation, resource controls, reliable scan time windows, findings with packet evidence, conversation analysis, and CSV export. These features are not yet implemented.

Analyze only traffic you own or have permission to inspect.
