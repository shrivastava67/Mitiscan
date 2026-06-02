# Threat Model

We use **STRIDE** plus a supply-chain lens, since Mitiscan is both a CLI and
a downloaded artifact.

## Assets

| Asset                        | Why it matters                                  |
|------------------------------|-------------------------------------------------|
| Target credentials in memory | Cred-brute / API audit modules hold secrets     |
| Run artifacts on disk        | Findings can be sensitive (PII, vuln details)   |
| Authorization receipt        | Proves the operator asserted permission         |
| Code-execution boundary      | Mitiscan spawns external scanners w/ user input |
| Release artifacts (wheel)    | Supply-chain trust anchor for downstream users  |

## Trust boundaries

1. **Operator ↔ Mitiscan** — operator is trusted to choose a lawful target.
   Enforced by `--authorized` gate and the GUI checkbox.
2. **Mitiscan ↔ target host** — adversarial. Output may contain crafted
   strings; reporter must escape on render.
3. **Mitiscan ↔ external tools** (`nmap`, `nuclei`, …) — semi-trusted. We
   assume the binaries are not adversarial but their output is.
4. **Mitiscan ↔ PyPI / OS package repos** — trust-on-first-use. Mitigated
   by pinning and signature verification on release.

## Threats and mitigations

| STRIDE             | Threat                                              | Mitigation                                                                 |
|--------------------|-----------------------------------------------------|----------------------------------------------------------------------------|
| Spoofing           | Attacker publishes a typo-squatted `mit1scan` pkg   | We publish only from tagged CI, signed with Sigstore, attested provenance. |
| Tampering          | Release wheel modified in transit                   | Sigstore signature + GitHub attestation; verify via `gh attestation`.      |
| Repudiation        | Operator denies running a destructive scan          | `audit.jsonl` (append-only style) + `authorization.txt` receipt per run.   |
| Information disc.  | Secrets leak into logs / reports                    | `core.logging` redacts known sensitive keys before write.                  |
| Denial of service  | Aggressive scan against critical infra              | Default deny on loopback/multicast/link-local; RFC-1918 gate.              |
| Elevation of priv. | Crafted target name → command injection            | `safety.normalize_target` regex-validates; subprocess uses `exec`, no shell.|
| Supply chain       | Compromised dependency                              | Dependabot weekly; pip-audit in CI; CodeQL; OSSF Scorecard.                |
| Supply chain       | Compromised CI step                                 | Pinned action versions; minimum-required `permissions:` per workflow.      |

## Out of scope

- The target system's security. Mitiscan is the offense, not the defense.
- Operator OPSEC (your hostname, your IP).
- Physical / insider attacks on the operator's machine.

## Hardening guarantees (today)

- Subprocesses spawn with `exec` (no shell expansion).
- Sensitive log keys redacted.
- Target normalization rejects shell metacharacters by construction.
- Deny list rejects loopback / multicast / IPv6 link-local by default.
- `--allow-private` is the only escape hatch for RFC-1918.
- Soft-then-hard timeout on long-running children.

## Roadmap

- Sandbox subprocess execution (Linux: `seccomp`, `landlock`).
- Per-module capability declaration (`requires: dns, http`) for least-privilege containers.
- Reproducible builds: `SOURCE_DATE_EPOCH` everywhere.
- Hardware-key-signed releases (Sigstore TUF root).
