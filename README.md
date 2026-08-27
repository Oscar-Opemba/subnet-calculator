# CIDR Subnet Calculator

Calculate network boundaries, host counts, and address ranges offline.

This is a small, dependency-free Python 3 defensive utility designed for local learning, code review, and authorized security validation. It provides both a command-line interface and a localhost-only interactive web form.

## Quick start

```bash
python3 app.py --web
```

Open <http://127.0.0.1:8091> in a browser. For CLI-capable tools, run `python3 app.py --help` to see the positional form.

## Scope and privacy

Use this only with systems, files, logs, or URLs you own or are explicitly authorized to assess. Network-enabled checks make a single bounded request to the exact host or URL you enter; they do not crawl, enumerate ports, brute-force credentials, exploit a vulnerability, or bypass access controls. Offline tools do not transmit their inputs. Never paste production passwords, session tokens, or private keys into a browser-hosted service.

Results are heuristic review aids rather than proof of security. Validate important findings with your organization’s policies, logs, asset inventory, and an appropriate authorized testing process.

## Test

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT. See [LICENSE](LICENSE).

## Context

The checks are aligned with defensive categories in the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/) and, for TLS-oriented review, the type of configuration analysis described by [Qualys SSL Labs](https://www.ssllabs.com/ssltest/).
