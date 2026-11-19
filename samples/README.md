# Synthetic sample lab

`lab.py` generates ten named PCAP scenarios without sockets or traffic transmission: normal, port_scan, host_discovery, syn_flood, brute_force, arp_spoofing, dns_tunneling, icmp_flood, exfiltration and beaconing. All timestamps and endpoints are synthetic. Exfiltration is a roughly 5 MB repeated-payload fixture; it does not contain stolen data. Encoded-looking DNS labels use example.test. Repeated SSH SYNs do not contain or prove authentication attempts.

Use Capture lab in the UI; each sample travels through the same upload API and detector engine as a user capture. Fixtures can trigger overlapping indicators (e.g. concentrated SYN bursts and repeated service connections). This is expected and is not a claim that multiple attacks occurred.

Existing demo_conversation.pcap contains 16 packets: handshake #1–3, data #4/#6/#7, close #9–12, partial setup #13–14, reset exchange #15–16. Generate with `python samples/make_conversation.py`. The original demo_scan.pcap is retained and now produces a scan indicator under default settings.

Fixtures exercise rule logic, not realism or detection accuracy. Generate additional benign lookalikes and real sanitized captures for evaluation before making efficacy claims.

The default **Four suspicious activities (demo)** sample combines port scanning, conflicting ARP claims, DNS tunneling indicators and an ICMP flood. It produces four findings with default settings. All traffic is generated offline.

Choose **Four suspicious activities (demo)** and use **Analyze lab capture**. With default settings this synthetic capture yields 5 IP addresses, 3 unique IP-pair communications, 4 protocols (TCP, ARP, DNS, ICMP), 321 packets, 4 findings and 2 high-severity findings. The activity-type card reports 4 detected out of 9 enabled categories; changing settings can change detection results.
