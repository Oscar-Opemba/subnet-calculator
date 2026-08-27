# Hardening notes

This release upgrades the original prototype with a shared hardened local server and per-tool safeguards.

| Area | Hardening applied |
| --- | --- |
| Web server | Loopback-only bind, threaded daemon workers, request-size cap, form-field cap, 10-second socket read timeout, per-client rate limiting, no-store cache policy, CSP, frame denial, MIME sniffing protection, and silent access logging. |
| Network behavior | One explicit request, short timeout, bounded response reads, redirects disabled, strict URL/hostname validation, credential-bearing URLs rejected, and private/reserved targets blocked by default where the tool performs target checks. |
| Offline privacy | Inputs stay local, sensitive output is redacted or omitted, output is capped, and no shell execution or dynamic code evaluation is used. |
| Reliability | Explicit error paths, input length limits, type validation, deterministic tests, and GitHub Actions CI for compilation and unit tests. |

These are still review aids, not a substitute for a complete security program. Use only on systems and data you own or are authorized to assess.
