# Security and privacy

Use on localhost for the demonstration. Captures can contain private identifiers, credentials and application content. Never upload captures without permission. The app does not send capture data to external services, automatically visit URLs, connect to captured IPs or execute extracted content.

Implemented controls: extension/signature validation, bounded request body and file read, validated rule policy, packet cap, one disposable worker, wall-clock timeout with child cleanup, Unix worker CPU/address-space limits, rate limiting, explicit no-CORS policy, same-origin upload checks, escaped captured strings, restrictive CSP, no-sniff headers, safe filename display, random report IDs plus independent bearer tokens, bounded expiring report cache and UploadFile closure on success/failure. Temporary multipart spools may exist in the OS temp directory and are not permanent uploads. Report expiry removes server access immediately and the periodic sweep frees retained metadata within 30 seconds. Browser copies remain until navigation/reload or tab close.

No authentication accounts, authorization roles, distributed quotas, persistent case store or multi-worker cache are provided. Bearer tokens isolate unguessable report access but are not a replacement for a public-service user/session model. Rate limits are global per process. Windows has no OS-enforced worker memory ceiling. The parser is custom and has not had a formal audit or extensive fuzz campaign. Public deployment needs request/time/memory limits at the reverse proxy/container boundary and a security review.

Redaction is pseudonymization, not guaranteed anonymization. It removes the filename and replaces observed IP/MAC/DNS identifiers; timing, ports, protocol and size patterns remain. Review reports before sharing. No raw payloads or hex dump are retained. HTTP parsing stores method/status only; TLS decoding exposes record headers, not SNI, certificates or decrypted content.

Run `python -m pip_audit -r requirements.lock` regularly. A clean advisory scan is not proof of security. The 2026-11-18 resolved dependency audit found no known advisories; see dependency-audit.json. requirements.lock pins the installed runtime versions audited in this session; requirements.txt retains allowed upgrade ranges.

For vulnerability reports, contact the project owner privately through a channel they designate. Do not attach real private captures or credentials to public issues. No invented security contact or license is supplied.
