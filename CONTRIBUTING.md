# Contributing

Thanks for helping improve this defensive cybersecurity utility. Before opening an issue or pull request, please confirm that the change remains safe for local learning and authorized validation.

Good contributions include clearer explanations, deterministic tests, accessibility improvements, better input validation, privacy-preserving output, and support for defensive log or configuration formats. Please include a small sanitized fixture when a bug depends on input data.

Do not submit payloads, persistence, credential attacks, exploit delivery, evasion, process injection, port scanning, domain fronting, or code that silently contacts third-party targets. Network checks must remain bounded to the explicit target and must not bypass access controls.

Run `python3 -m unittest discover -s tests -v` before submitting a pull request. Never include real credentials, tokens, private keys, personal data, or customer target information in issues, fixtures, screenshots, or commits.
