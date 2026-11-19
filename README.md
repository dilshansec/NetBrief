# NetBrief

NetBrief analyzes saved Wireshark capture files (`.pcap` and `.pcapng`) on your computer. It shows a basic traffic summary and highlights suspicious activity with the packet numbers that support each finding.

## What it does

- Summarizes IP addresses, communications, protocols and packet counts.
- Checks for nine types of suspicious behavior, including scanning, floods, ARP conflicts, DNS tunneling indicators and unusual outbound transfers.
- Shows severity, explanations and evidence packet numbers to review in Wireshark.
- Exports findings as JSON, CSV or a printable report.

It analyzes uploaded captures, not live traffic. Findings are indicators to investigate, not proof of an attack.

## How to use it

Install **Python 3.10 or later**, then download this repository as a ZIP and extract it, or clone it:

```bash
git clone https://github.com/dilshansec/NetBrief.git
cd NetBrief
```

**On Windows:** double-click `start_windows.bat`. Keep its terminal open while using the tool.

**On Linux/macOS:** run:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn netsentry.main:app --host 127.0.0.1 --port 8000
```

1. Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.
2. Choose a capture file and click **Analyze capture**.
3. Review **Basic details**, then **Suspicious activity** below it.
4. Expand a finding for its explanation, and use the displayed packet numbers to check the evidence in Wireshark.

To try it without your own file, open **Try a sample capture**, select **Four suspicious activities (demo)** and click **Analyze lab capture**.
