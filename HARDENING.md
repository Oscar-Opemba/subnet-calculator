# Defense-in-depth hardening

This release adds a second hardening layer on top of the original defensive boundary.

## Shared controls

| Control | Implementation |
| --- | --- |
| Loopback server boundary | The interactive server binds to IPv4 loopback only, rejects non-loopback peers, accepts only GET and POST, enforces an allowlisted local Host header, closes connections, and returns a strict `Allow` header for unsupported methods. |
| Request limits | Port validation, 1 MB body cap, 32 form-field cap, 64-header cap, 8 KB header-value cap, 10-second socket timeout, and 30 requests per client per minute. |
| Browser isolation | `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Cross-Origin-Resource-Policy`, `Permissions-Policy`, `Referrer-Policy`, and no-store cache headers. |
| Browser request integrity | Forms carry a per-process CSRF token and POST requests verify it with constant-time comparison before analysis. |
| SSRF and rebinding resistance | HTTP requests disable proxies and redirects, validate methods and body size before DNS, resolve public addresses, connect to the resolved IP, and preserve the original hostname for HTTP Host/SNI verification. Private, loopback, link-local, reserved, multicast, unspecified, and non-public resolutions are rejected by default. |
| Local file safety | Inputs are type-checked, path length and NUL bytes are rejected, symlinks are refused with `O_NOFOLLOW` where available, regular-file type is verified with `fstat`, and reads are bounded in chunks. |
| Supply-chain safety | CI, CodeQL, dependency review, and OpenSSF Scorecard actions are pinned to immutable commit SHAs with least-privilege permissions and bounded job timeouts. |

## Tool-specific controls

JWT decoding now uses strict Base64URL validation and warns on external key references and malformed critical headers. TLS inspection connects through the verified IP-pinned helper while retaining certificate trust-store and hostname verification. Subnet calculations skip host enumeration above one million addresses. Other tools inherit the same network, parser, and output constraints and retain their domain-specific caps and redaction behavior.

## Audit coverage

The HTTP Security Headers Checker includes a local simulated-penetration-test harness covering synthetic header inspection, redirect rejection, malformed and private-target rejection, response-header assertions, unsupported methods, unsupported content types, missing CSRF tokens, oversized requests, and rate limiting. The harness uses only a loopback fixture and never contacts an external target.

## Residual risk

These are local defensive utilities, not hardened multi-user production services. They do not provide user authentication, encrypted browser transport, full DNSSEC validation, signature verification for JWTs, or a complete vulnerability-management workflow. The CSRF token protects the local form flow but is not a substitute for authentication. Use only on systems and data you own or are explicitly authorized to assess, and review important results in context.
