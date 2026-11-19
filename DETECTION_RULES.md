# Detection rules

Implementation: `netsentry/detectors/rules.py`; envelope/coverage: `netsentry/detectors/__init__.py`; validated defaults: `netsentry/config.py`.

All rules are heuristics. ATT&CK IDs are conditional behavioral mappings, not attribution or proof. No tool identity (including Nmap) or successful compromise is inferred. Severity is potential impact, confidence is evidence strength. No rule currently emits high confidence.

| Category / key | Default trigger | Confidence / severity | Main limitations and benign explanations |
|---|---|---|---|
| Port scan / `port_scan` | ≥20 distinct destination ports OR ≥20 destination hosts from a source in 60s; SYN, UDP, FIN-only, NULL or FIN/PSH/URG packets | Medium / medium | Authorized scanners and service fan-out; does not confirm scan tool; reports matched SYN/ACK and completed-handshake counts to help assess connect-style activity; DNS-classified UDP is excluded |
| Host discovery / `host_discovery` | ≥20 targets per source in 60s, using ICMP echo, ARP requests or TCP SYN | Medium / low | Ordinary ARP, inventory and monitoring; overlaps with horizontal scanning |
| SYN flood / `syn_flood` | ≥200 SYNs to the same destination/port in 60s and observed SYN/ACK:SYN ratio <0.2 | Medium / high | Asymmetric visibility, capture loss, retries and legitimate bursts; aggregate reverse-response ratio drives the trigger; matched SYN/ACK and completed-handshake counts/ratio are supporting indicators, with capture-order/session-reuse limits |
| Repeated auth-service connections / `brute_force` | ≥20 distinct (source, source port, sequence) SYN attempts to 21/22/23/80/443/3389, or ≥20 observed HTTP 401 / FTP 530 responses per endpoint/service in 60s | Low for connection-only; medium for responses / medium | Encrypted authentication is opaque; reconnections/health checks are benign lookalikes; HTTP challenges need not represent bad passwords; no compromise claim |
| ARP mapping conflicts / `arp_spoofing` | ≥2 sender MAC claims for one nonzero sender IPv4 in 60s | Medium / high | Failover, proxy ARP, DHCP changes, virtualization, replacement. Gateway identity and unsolicitedness are not established |
| DNS tunneling indicators / `dns_tunneling` | ≥20 distinct names with first label ≥32 characters and Shannon entropy ≥3.5 bits/character, per source/last-two-label parent in 60s | Low / medium | CDN/telemetry/tracking names; last-two-label grouping is not public-suffix-aware; no decoded answer-content or baseline scoring |
| ICMP flood / `icmp_flood` | ≥200 ICMP/ICMPv6 echo requests per destination in 60s | Medium / high | Monitoring, diagnostics or tests; no complete request/reply session matching |
| Large outbound transfer / `exfiltration` | ≥5,000,000 captured bytes internal→external, aggregate destination ratio ≥5:1 | Low / medium | No reliable baseline; backups/cloud sync/uploads; counts headers and duplicates; no intent or sensitive-content inference |
| Periodic connections / `beaconing` | ≥8 distinct TCP SYN attempts per source/destination/service; span ≥60s; all gaps ≥1s; interval coefficient of variation ≤0.15 | Low / medium | Heartbeats, update agents and monitoring; no UDP/DNS periodicity or jitter-tolerant advanced models |

Time-window rules use fixed epoch-aligned buckets (default 60 seconds). Activity spanning a boundary may be missed. Exfiltration and beaconing operate across the capture. Change thresholds and enabled rules in the UI and reanalyze; current reports retain their original policy.

Defaults for internal scope: 10/8, 172.16/12, 192.168/16, fc00::/7. Public documentation ranges used in synthetic fixtures are treated as external; adjust CIDRs for your environment.

## Evidence contract

Each finding contains a report-local unique ID, title/category, severity/confidence, source/destination address and port sets, first/last times, packet numbers, flow IDs, observed indicators and thresholds, window, explanation, benign explanations, investigation recommendations, limitations, optional ATT&CK technique IDs and analyst status. Up to 100 findings per rule and 1,000 packet references per finding; `evidence_total` reports the full matching count. Large indicator sets can be summarized in the interface; JSON contains the reported values.

Coverage distinguishes disabled rules, evaluated rules and rules lacking prerequisite decoded traffic. “Evaluated” does not mean sufficient visibility or a clean network. Trusted-host, authorized-scanner and domain allowlists annotate findings without lowering severity or suppressing evidence.

## Adding a detector

1. Implement a pure function `(packets, settings)` yielding `(supporting_packets, indicator_dict, confidence)` in a new module or rules.py.
2. Register it in RULES with a title, severity, defensible optional ATT&CK mapping and benign explanation. Add its key to Settings validation and frontend rule controls.
3. Add validated thresholds to Settings and document the signal, edge conditions and false positives.
4. Add controlled synthetic positive/negative captures, exact threshold tests and evidence-reference assertions. Never contact captured addresses or execute payloads.
5. Update coverage prerequisites and sample documentation. Run all regressions.
