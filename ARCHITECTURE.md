# Architecture

## Assessment

The original v0.2 was a small FastAPI/static-JavaScript protocol teaching application. Its dependency-free parser, accurate TCP sequence/acknowledgment matching, exact event frame references, AND-combined filters, demo conversation and pagination were working. It had no attack detection, ARP/DNS content analysis, resource isolation, rate limit, per-analysis access control, host inventory or investigation workflow. See IMPLEMENTATION_PLAN.md.

## Data path

Browser multipart upload → validated per-analysis Settings → bounded upload read → disposable Python subprocess → parser → existing Conversations + host/flow inventory → independent detectors → evidence envelopes/coverage → expiring in-memory report → bearer-protected paginated packet retrieval → browser views.

No architecture migration or database. No network calls from packet analysis. The original TCP evidence subsystem is preserved and regression tested.

## Resource model

Defaults: 10 MiB upload, 50,000 frames, 45 seconds wall clock, one worker, four cached analyses, 900-second report lifetime. Expired entries are denied immediately and swept every 30 seconds or on subsequent uploads. Retention can therefore exceed the access deadline by up to the sweep interval. Server restart discards all reports. Any successful upload can evict the oldest report at capacity.

The bounded capture is read once into memory; frame decoding iterates without constructing a second raw packet list. Metadata is retained for investigation, and subprocess serialization adds copies. This is **bounded in-memory processing, not a streaming large-capture engine**. The API defaults to no packet array in the initial response and offers 1,000-row maximum pages. Other inventories remain bounded by the capture limit and are returned initially. The UI downloads metadata pages, renders 100 packet rows at a time and retains the metadata in browser memory.

Unix worker resource limits: 512 MiB virtual address space and 30 CPU seconds; Windows lacks these resource-module controls. Worker timeout kills and waits for the child. File and packet caps still apply on both systems. UploadFile cleanup happens on success, validation errors and worker failures; multipart spools may temporarily use the OS temp directory.

## Investigation semantics

Flows are bidirectional protocol + endpoint/port pairs, including UDP. They can group reused sessions and are not connection identities. The original TCP explanation limits remain 200 pairs / 80 detailed events each. Flow byte counts describe captured frame bytes, not unique application bytes. TCP payload byte totals can include retransmissions.

Incidents group equal source sets and UTC minute of first observation; no causal relationship is inferred. Every finding separates severity from confidence. Trusted entities are annotated, never silently suppressed. Rule disablement is explicit in coverage. Packet timestamps can be unavailable; time-window rules omit such packets.

Browser analyst statuses and settings are ephemeral. Reports omit raw payloads. Pseudonymization replaces observed IPs, MACs and DNS names, removes the filename and network policy identifiers; timestamps, ports and statistical structure remain. Review exports before sharing. The user can opt out of redaction.

## Future priorities

Rolling windows and better sessionization; public-suffix-aware DNS analysis; decoded DNS answers and TLS handshake metadata; server-side virtualized filtering; persisted cases with actual user authentication; container-level worker resource isolation; larger representative benign datasets; ongoing fuzz testing and independent security review.
