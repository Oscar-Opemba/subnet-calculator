# Product contract

## Trust boundary

This tool is a local defensive utility for systems and data that the operator owns or is explicitly authorized to assess. It does not persist submitted values, accept credentials, execute shell commands, or provide a hosted multi-user service.

## Interfaces

The CLI is the stable automation interface. Run `python3 app.py --help` for flags. Successful CLI operations print a JSON object to standard output; invalid input is represented as a JSON `error` field where the tool performs analysis. The optional local web interface is intended for loopback use only and uses the same analyzer function.

The analyzer contract is `analyze(values: dict) -> dict`. Input values are strings from a CLI or URL-encoded form. Outputs are JSON-serializable dictionaries with bounded strings and tool-specific findings. Callers must treat findings as review signals rather than proof of compromise or compliance.

## Operational limits

The shared server enforces loopback binding, CSRF-protected POST forms, GET/POST-only behavior, request and output limits, a concurrency cap, rate limiting, no-store responses, and browser isolation headers. Network-enabled tools use public-target validation, bounded timeouts and response reads, no proxy inheritance, no redirects, and resolved-IP pinning. File-enabled tools use regular-file checks, symlink resistance where supported, and bounded reads.

## Compatibility

Supported runtime: Python 3.11 or later. The project has no runtime dependency beyond the Python standard library. The package metadata and CI workflow are the source of truth for installation and supported execution.

## Non-goals

This tool is not a general vulnerability scanner, exploit framework, credential validator, compliance certification, or replacement for incident response and professional security review.
