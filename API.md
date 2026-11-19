# API

Same-origin FastAPI API. Machine-readable OpenAPI at `/openapi.json`; this offline text reference is served at `/api/docs`. No external documentation assets are requested.

| Method / endpoint | Purpose |
|---|---|
| GET `/api/health` | Version and process health |
| GET `/api/config` | Default validated settings and server resource limits |
| POST `/api/analyze` | Multipart `file` and JSON-string `settings` (optional); waits for bounded analysis |
| GET `/api/analyses/{id}/status` | Complete status for a retained analysis |
| GET `/api/analyses/{id}/summary` | Capture summary |
| GET `/api/analyses/{id}/packets` | Packet pages with `offset`, `limit` (1–1000), `query`, `ip`, `protocol` |
| GET `/api/analyses/{id}/{section}` | Paginated `alerts`, `hosts`, `flows`, `timeline`, `coverage` |
| GET `/api/analyses/{id}/alerts/{alert_id}/evidence` | Alert envelope and capped supporting packet metadata |
| GET `/api/samples` | Synthetic lab catalog |
| GET `/sample/lab/{name}` | Generated offline PCAP fixture |
| GET `/sample/conversation` | Existing 16-packet teaching capture |

Successful upload returns `analysis_id`, `access_token`, `status: complete`, inventories, settings, findings, `packet_count` and an empty `packets` array by default. Send `Authorization: Bearer <access_token>` to analysis endpoints. Identifier and token are independent high-entropy random values; token is never placed in a URL. Treat it as a bearer secret. Missing, incorrect and expired authorization all produce 404.

`?include_packets=true` is an explicitly requested compatibility option; avoid it for larger captures. Pagination response: `{total, offset, items}`. IDs live only in one server process. Multiple Uvicorn workers are unsupported because storage/admission/rate-limit state is process-local.

Errors use FastAPI `{detail: ...}`. Relevant statuses: 400 malformed capture or body, 403 cross-origin upload, 408 worker timeout, 411 missing Content-Length, 413 oversize, 422 invalid settings/query or failed worker, 429 concurrency/rate limit, 404 expired/unauthorized results. Validation errors may use FastAPI's structured detail array. No packet payloads appear in logs/error text.

Analysis is synchronous request/response with indeterminate UI progress, not a background job queue. There is no live percent-complete status. Analyst status changes and export generation currently happen in the browser; no persistence/report-download API is claimed.
