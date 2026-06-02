# Mitiscan

[![CI](https://github.com/shrivastava67/Mitiscan/actions/workflows/ci.yml/badge.svg)](https://github.com/shrivastava67/Mitiscan/actions/workflows/ci.yml)
[![CodeQL](https://github.com/shrivastava67/Mitiscan/actions/workflows/codeql.yml/badge.svg)](https://github.com/shrivastava67/Mitiscan/actions/workflows/codeql.yml)
[![OSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/shrivastava67/Mitiscan/badge)](https://securityscorecards.dev/viewer/?uri=github.com/shrivastava67/Mitiscan)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](pyproject.toml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/contributor%20covenant-2.1-purple.svg)](CODE_OF_CONDUCT.md)

Enterprise-grade automated VAPT platform. 35 specialized modules, async
orchestration, conditional NIST SP 800-115 / OWASP reporting.

> ⚠️ **For authorized security testing only.** See
> [Disclaimer](#disclaimer) and [SECURITY.md](SECURITY.md).

## One-Command Quickstart

```bash
git clone https://github.com/shrivastava67/Mitiscan.git && cd Mitiscan && python mitiscan.py
```

First run auto-installs Python dependencies, then launches the GUI.

For containers:

```bash
docker run --rm ghcr.io/shrivastava67/mitiscan:latest --check-deps
```

## Highlights

- **35 modules** — passive OSINT → active recon → web/API/CMS/DB/cloud/IoT
  audit → consolidation with CVE/CWE/CVSS mapping.
- **Async DAG engine** — parallel within stages, sequential between, with
  per-module checkpointing and `--resume`.
- **Profile-aware evasion** — STEALTH / BALANCED / AGGRESSIVE concurrency
  and timing.
- **Conditional reporting** — Jinja2 templates emit HTML / Markdown / JSON
  (+ PDF via WeasyPrint). Empty sections are purged automatically.
- **Authorization gate** — `--authorized` flag and a written receipt per run.
- **Hardened by default** — RFC-1918 / loopback / multicast deny list,
  shell-injection-safe subprocess spawn, secret-redacted structured logs.
- **Supply-chain trust** — Sigstore-signed releases, CycloneDX SBOM, GitHub
  attestations, weekly Dependabot + pip-audit + CodeQL.

## Modules

<details>
<summary>Click for the 35-module list</summary>

1. Bootstrap / dependency self-heal
2. Passive OSINT (`amass`, `subfinder`, `theHarvester`)
3. Active subdomain (`shuffledns`, `massdns`, `puredns`)
4. Reverse DNS / Geo (`dnsx`, `whois`)
5. Threat intel / leaked creds (`h8mail`)
6. Live host discovery (`nmap`, `masscan`, `fping`)
7. Full port + service (`masscan` → `nmap -sV`)
8. WAF / IDS detect (`wafw00f`)
9. SSL / TLS audit (`testssl.sh`, `sslyze`)
10. Net proto audit (SNMP / DNS-AXFR / NTP / IKE)
11. SMB / RPC / NetBIOS (`smbmap`, `enum4linux-ng`)
12. AD / Kerberos (`netexec`, `impacket`, `kerbrute`)
13. SSH / FTP / Telnet (`ssh-audit`)
14. DB discovery (`nmap` DB scripts)
15. Web HTTP filter (`httpx`)
16. Web fingerprint (`whatweb`, `nikto`)
17. Dir / file fuzz (`feroxbuster`, `ffuf`)
18. Param fuzz (`arjun`, `ffuf`)
19. API audit (`kiterunner`, schema parsers)
20. XSS (`dalfox`, `xsstrike`)
21. SQLi (`sqlmap --batch`)
22. SSRF / LFI / RFI (`ffuf`, `lfimap`)
23. CMDi / SSTI (`tplmap`, `commix`)
24. CMS (`wpscan`, `joomscan`, `droopescan`)
25. AuthN / session
26. Subdomain takeover (`subjack`, `nuclei`)
27. Nuclei templates
28. Credential brute (`hydra`)
29. Cloud storage (`cloudbrute`, `s3scanner`)
30. Container (`kube-hunter`)
31. CI/CD / Git exposure (`gitjacker`)
32. IoT / firmware (`firmwalker`)
33. Evasion validation (internal)
34. Post-exploit sim (`linpeas` artifact parse)
35. Consolidation / dedup / CVE-CWE-CVSS mapping

</details>

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full diagram and
package boundaries. TL;DR:

```
CLI / GUI → Engine (async DAG) → Modules → Reporter → mitiscan_outputs/<run_id>/
                              ↘
                                core.logging  →  mitiscan.jsonl
                                core.logging  →  audit.jsonl
```

## Modes

```bash
python mitiscan.py                                          # GUI
python mitiscan.py --check-deps                             # audit dependencies
python mitiscan.py --bootstrap                              # install missing tools
python mitiscan.py --headless example.com --authorized --profile BALANCED
python mitiscan.py --resume <run_id>                        # resume an interrupted scan
```

Full reference: [docs/USAGE.md](docs/USAGE.md).
Deploying to CI / Kubernetes / air-gap: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Security Posture

| Concern             | Control                                                    |
|---------------------|------------------------------------------------------------|
| Vulnerability intake| [SECURITY.md](SECURITY.md), private advisories             |
| Static analysis     | CodeQL (security-extended + security-and-quality)          |
| Dependency review   | Dependabot weekly + `pip-audit` in CI                      |
| Secret scanning     | gitleaks in CI + pre-commit                                |
| Build provenance    | Sigstore signature + GitHub attestation on every release   |
| SBOM                | CycloneDX, attached to every release                       |
| Scorecard           | OSSF Scorecard published weekly                            |
| Container           | Multi-stage, non-root (uid 10001), runtime-only image      |
| Branch protection   | Required reviews + green CI on `main`                      |

Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Project Health

- [Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1)
- [Contributing Guide](CONTRIBUTING.md) (DCO sign-off required)
- [Support](SUPPORT.md)
- [Changelog](CHANGELOG.md)
- [Citation](CITATION.cff)

## Disclaimer

For authorized security testing only. Use only on systems you own or have
explicit written permission to test. The authors disclaim all liability
for misuse. See [LICENSE](LICENSE).
