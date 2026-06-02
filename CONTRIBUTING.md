# Contributing to Mitiscan

Thanks for considering a contribution. This doc covers setup, workflow, and
standards.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you agree to uphold it.

## Reporting Security Issues

**Do NOT open a public issue for security vulnerabilities.** See
[SECURITY.md](SECURITY.md) for the private disclosure process.

## Ground Rules

- Be respectful. Disagree with ideas, not people.
- Discuss large changes in an issue *before* opening a PR.
- All contributions are licensed under the project [LICENSE](LICENSE) (MIT).
- All commits must be signed off (DCO). Use `git commit -s`.

## Dev Setup

```bash
git clone https://github.com/shrivastava67/Mitiscan.git
cd Mitiscan
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Workflow

1. Fork & branch from `main` — `git checkout -b feat/short-name`
2. Make focused commits. Conventional Commits encouraged (`feat:`, `fix:`,
   `docs:`, `refactor:`, `test:`, `chore:`).
3. Add or update tests. Run `make ci` locally.
4. Sign off your commits: `git commit -s`.
5. Push and open a PR against `main`. Fill the PR template.
6. CI must be green. A maintainer will review.

## Quality Gates

Run before pushing:

```bash
make fmt          # ruff + black
make lint         # ruff
make typecheck    # mypy
make test         # pytest + coverage
make security     # bandit + pip-audit
```

Or the umbrella:

```bash
make ci
```

## Coding Standards

- Python ≥ 3.10. Type hints on all public functions.
- Format: black (line length 100). Lint: ruff. Type-check: mypy.
- No `print()` for diagnostics in library code — use the structured logger
  in `core/logging.py`.
- New modules ship with at least a smoke test.

## Adding a Scanner Module

1. Add a coroutine to `modules/modules.py` returning a `ModuleResult`.
2. Document its state transitions (PENDING → RUNNING → COMPLETED/SKIPPED/
   NOT_APPLICABLE/FAILED).
3. Register it in the engine DAG.
4. Add a smoke test in `tests/modules/`.

## Commit Message Format

```
<type>(<scope>): <subject>

<body — what and why, not how>

Signed-off-by: Your Name <you@example.com>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`,
`ci`, `chore`, `revert`.

## Reviewing PRs

- Be kind. Assume good intent.
- Block on correctness, security, breaking API. Suggest on style.
- Prefer concrete code suggestions over abstract critique.

## Releasing

Maintainers cut releases via tagged commits (`vX.Y.Z`). The release workflow
builds the wheel, generates an SBOM, signs artifacts with Sigstore, and
publishes to PyPI.
