# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- pyproject.toml with PEP 621 metadata, console entry `mitiscan`, ruff/
  black/mypy/pytest/coverage/bandit config.
- Community files: CODE_OF_CONDUCT, CONTRIBUTING, SECURITY, SUPPORT,
  CHANGELOG, CITATION, CODEOWNERS, issue + PR templates.
- CI: lint + typecheck + test matrix, CodeQL, dependency-review, gitleaks,
  OSSF Scorecard, SBOM, signed releases.
- pre-commit config (ruff, black, mypy, bandit, gitleaks, end-of-file).
- Dependabot (pip + github-actions).
- Multi-stage Dockerfile (non-root, distroless final).
- Structured logger and audit log writer (`core/logging.py`).
- Version module (`core/version.py`) — `__version__`, build info.
- Test scaffolding under `tests/` with smoke tests for core modules.
- Architecture, Threat Model, Usage, Deployment docs under `docs/`.
- Makefile umbrella targets (`make ci`, `make fmt`, etc.).

### Changed
- README rewritten with badges, one-command install, and policy links.
- `mitiscan.py` auto-installs Python deps on first launch.

### Security
- Authorization gate enforced for headless scans (`--authorized`).
- All long-running subprocesses use `soft_timeout` (SIGTERM before SIGKILL).

## [0.1.0] — 2026-06-02

### Added
- Initial public release. 35 scanner modules, async orchestration engine,
  Jinja2 NIST/OWASP report templates, customtkinter GUI.

[Unreleased]: https://github.com/shrivastava67/Mitiscan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/shrivastava67/Mitiscan/releases/tag/v0.1.0
