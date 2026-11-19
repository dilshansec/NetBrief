# Contributing

Retain the existing FastAPI/buildless JavaScript architecture unless there is a demonstrated need to change it. Keep parsing independent of views, and rules independent of the API. Escape captured text before HTML rendering. Never add active scanning, packet transmission, payload execution or automatic network enrichment.

Install requirements-dev.txt and run pytest plus the Node packet-filter regression suite. For detector changes include synthetic positive, negative, threshold-boundary and partial-visibility examples with packet evidence assertions. For UI changes exercise upload, the single-page summary and findings, exact evidence frame ranges, finding filters, responsive layout and export redaction. Document test limits instead of claiming production accuracy.

Do not include real user captures, secrets or copied proprietary datasets. Use samples/lab.py for harmless offline fixtures. Keep status, confidence and severity distinct. Document any new resource usage, data retention or outbound service integration. Ask the owner about licensing before adding a software license.
