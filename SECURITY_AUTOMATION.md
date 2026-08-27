# Automated security scanning

This repository runs two GitHub-native security automations.

## CodeQL

The `CodeQL` workflow analyzes Python source on pushes and pull requests to `main`, every Monday by scheduled run, and on manual dispatch. It uses the `security-extended` query suite and uploads results to the repository’s Code Scanning alerts when GitHub permits security-event writes.

The workflow is intentionally limited to static analysis. It does not execute user-supplied targets, send network probes, or access application credentials.

## Dependabot

Dependabot checks the Python dependency manifest and GitHub Actions references weekly on Monday. It opens a maximum of five pull requests per ecosystem, labels them `dependencies` and `security`, and uses scoped commit messages.

The projects primarily use the Python standard library, so the GitHub Actions ecosystem is expected to produce more update activity than the Python ecosystem. Review every update in CI before merging it.

## Maintainer response

Review CodeQL alerts and Dependabot pull requests promptly. Do not paste secrets, live target information, or proprietary logs into issues or pull requests. Validate security changes with the repository’s tests and preserve the project’s defensive, authorized-use boundary.
