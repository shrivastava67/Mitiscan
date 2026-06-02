# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.x     | :white_check_mark: |

Once we ship `1.0`, only the latest minor will receive security fixes.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via one of:

1. **GitHub Private Vulnerability Reporting** — preferred. Open
   <https://github.com/shrivastava67/Mitiscan/security/advisories/new>.
2. **Email** — security@mitiscan.dev (replace with your contact). Encrypt
   sensitive details with the maintainer's PGP key (publish at
   `https://github.com/shrivastava67.gpg`).

Include:

- A description of the issue and its impact.
- Steps to reproduce or a proof-of-concept.
- Affected version(s) and environment.
- Your suggested fix, if any.

## Response Targets

| Stage              | Target               |
|--------------------|----------------------|
| Acknowledgement    | Within 72 hours      |
| Triage + severity  | Within 7 days        |
| Patch (high/crit)  | Within 30 days       |
| Patch (med/low)    | Best effort          |
| Public disclosure  | Coordinated with you |

We follow **coordinated disclosure**. We will credit you in the advisory
(or anonymize on request).

## Scope

In scope:

- Code execution, privilege escalation, sandbox escape.
- Command injection via target input, run-id, or report fields.
- Path traversal in the artifact directory.
- Hard-coded secrets, weak crypto, insecure defaults.
- Supply-chain weaknesses (build, release, dependency).

Out of scope:

- Vulnerabilities in target systems being scanned (that's the point of the
  tool). Report those to the target owner.
- Issues that require physical access or a malicious local admin.
- Self-XSS or theoretical attacks without a credible attacker model.

## Hardening Guarantees

- Releases are signed with [Sigstore](https://www.sigstore.dev/).
- Each release ships a CycloneDX SBOM.
- CI runs CodeQL, gitleaks, pip-audit, and OSSF Scorecard.
- Branch protection: required reviews + status checks on `main`.

## Safe Harbor

We will not pursue legal action against good-faith researchers who:

- Make a reasonable effort to avoid privacy violations, data loss, or
  service disruption.
- Give us reasonable time to investigate and fix before public disclosure.
- Do not exploit beyond what is needed to demonstrate the issue.
