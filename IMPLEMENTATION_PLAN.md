# Repository assessment and implementation plan

The original v0.2 is FastAPI + buildless JavaScript, with a dependency-free PCAP/PCAPNG decoder. Working TCP handshake/close evidence, exact frame filtering, pagination and conversation samples will be preserved. There is no database, React build or external packet tool to migrate.

Gaps: no threat engine, DNS/ARP content decoding, host/flow inventory, investigation statuses or rule configuration. Upload analysis blocks the async route, reads a full bounded file, and returns all metadata. No timeout, admission control or rate limiting. Existing tests explicitly assert absence of alerts and require updating for the new capability.

1. Extend metadata decoding and aggregates; retain existing TCP evidence.
2. Add nine configurable heuristic categories, explainable evidence and synthetic fixtures.
3. Add isolated analysis execution, upload/resource limits, bounded expiring reports and paginated API access.
4. Extend the existing interface with threats, hosts, graph, timeline, settings and exports.
5. Run regressions, API/fixture tests and browser checks; document limitations and run localhost.

No public publication or license change. Optional capabilities not completed will be named explicitly in documentation.
