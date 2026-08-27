# Security automation and defense-in-depth

This repository uses GitHub-native automation and pinned workflow dependencies to reduce supply-chain and regression risk.

## CodeQL

The `CodeQL` workflow analyzes Python source on pushes and pull requests to `main`, every Monday at 03:30 UTC, and on manual dispatch. It uses the `security-extended` query suite and uploads results to Code Scanning alerts. The workflow is limited to static analysis and does not execute user-supplied targets.

## Dependabot

Dependabot checks Python manifests and GitHub Actions references weekly on Monday. It opens a maximum of five pull requests per ecosystem with `dependencies` and `security` labels. Dependabot security updates and automated security fixes are enabled in the repository settings.

## Dependency review

The `Dependency Review` workflow runs on pull requests to `main` and uses the GitHub dependency-review action to flag vulnerable additions before merge.

## OpenSSF Scorecard

The `OpenSSF Scorecard` workflow runs on pushes to `main`, every Monday, branch-protection changes, and manual dispatch. It publishes SARIF results to Code Scanning. Repository checkout disables credential persistence. Actions are referenced by immutable commit SHA with a version comment.

## Workflow supply-chain controls

Third-party and GitHub-maintained Actions are pinned to full commit SHAs rather than mutable tags. Workflows use least-privilege permissions, bounded job timeouts, concurrency cancellation, and `persist-credentials: false` where checkout is used for Scorecard analysis.

## CI quality gate

The tool CI matrix runs on Python 3.11, 3.12, and 3.13. It compiles the source, runs the unit and abuse-case suites, builds a wheel without runtime dependencies, and performs an offline install smoke test. The documentation-only hub uses a manifest-appropriate test workflow.

## Maintainer response

Review CodeQL, Dependency Review, Scorecard, and Dependabot findings before merging. Do not paste secrets, live target information, or proprietary logs into issues or pull requests. Preserve the project’s defensive and authorized-use boundary.
