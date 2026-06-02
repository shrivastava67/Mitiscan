# Mitiscan

Enterprise-grade automated VAPT platform. 35 specialized modules, async orchestration,
conditional NIST SP 800-115 / OWASP reporting.

## Architecture

```
mitiscan/
├── mitiscan.py            # entrypoint (launches GUI)
├── core/
│   ├── engine.py          # async orchestration engine
│   ├── scope.py           # target scope dataclass
│   ├── evasion.py         # adaptive throttle / WAF awareness
│   ├── result.py          # ModuleResult / State enums
│   ├── bootstrap.py       # self-healing dependency installer
│   └── reporter.py        # conditional HTML/MD report renderer
├── modules/
│   └── modules.py         # 35 module coroutines
├── gui/
│   └── app.py             # customtkinter frontend
├── templates/
│   └── report.html.j2     # Jinja2 NIST/OWASP report template
└── mitiscan_outputs/      # per-run artifact directory
```

## 35 Modules

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

## Conditional Reporting

Each module returns a `ModuleResult` carrying `state ∈ {PENDING, RUNNING,
COMPLETED, SKIPPED, NOT_APPLICABLE, FAILED}`. Reporter purges any module that
is not `COMPLETED` with findings — no blank headers in the final document.

## Run

One command — clones, auto-installs Python dependencies on first launch, opens the GUI:

```bash
git clone https://github.com/shrivastava67/Mitiscan.git && cd Mitiscan && python mitiscan.py
```

Other modes:

```bash
python mitiscan.py --check-deps        # audit dependencies (no install)
python mitiscan.py --bootstrap         # install missing tools (apt → pip → go → git)
python mitiscan.py --headless example.com --authorized --profile BALANCED
python mitiscan.py --resume <run_id>   # resume an interrupted scan
```

Target intake supports domain, IPv4, or CIDR. GUI shows live module state +
backend stdout. Final HTML + Markdown + JSON (+ PDF if `weasyprint` installed)
land in `mitiscan_outputs/mitiscan_outputs_<runid>/`.

## Implemented Enhancements

1. `--check-deps` dry-run audit
2. Per-tool version probe + minimum-version gate
3. Idempotency cache at `~/.mitiscan/bootstrap.json` (24h TTL on `apt-get update`)
4. PEP-668 handling — auto-venv when Python is externally-managed
5. PATH augmentation — `$HOME/go/bin`, `~/.local/bin`, venv `bin/` injected per subprocess
6. Wildcard DNS filter on `puredns` brute (M03)
7. Global URL dedup set on engine (`engine.seen_urls`, `engine.see()`)
8. CVSS vector field carried end-to-end through finding dicts
9. Finding dedup by normalized title + target (no near-duplicates)
10. Tech-stack-driven gating — M17 skipped on schema'd API hosts
11. Per-module checkpoint + `--resume <run_id>` survival
12. Parallel module DAG — modules within a stage run concurrently (sequential under STEALTH)
13. `soft_timeout` for long runs (nmap, puredns, nuclei) — graceful SIGTERM before SIGKILL
14. PDF export via `weasyprint`
15. Authorization gate — GUI checkbox + CLI `--authorized` flag + `authorization.txt` receipt

## Disclaimer

For authorized security testing only. Use only on systems you own or have
explicit written permission to test.
