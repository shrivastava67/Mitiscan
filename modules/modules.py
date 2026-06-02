"""All 35 Mitiscan modules.

Each module is an `async def m_xx(engine)` coroutine that:
  1. Checks its skip condition. If skip, returns engine.skip(...).
  2. Builds a subprocess command, calls engine.run_cmd(...).
  3. Parses output (JSON/XML/TXT), maps to findings list.
  4. Updates engine.scope with discovered data for downstream modules.
  5. Returns engine.done(mid, findings, artifacts, cves, cwes).

Findings dict schema:
    {
      "title": str, "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "target": str, "cve": str|None, "cwe": str|None,
      "cvss": str|None, "description": str, "remediation": str,
    }
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from core.bootstrap import bootstrap
from core.result import ModuleResult

if TYPE_CHECKING:
    from core.engine import Engine


# =========================================================================== #
#  M01 — Bootstrap                                                            #
# =========================================================================== #
async def m01_bootstrap(e: Engine) -> ModuleResult:
    rep = await bootstrap(check_only=False)
    findings = []
    if rep.failed:
        findings.append({
            "title": "Dependency install failures",
            "severity": "MEDIUM",
            "target": "localhost",
            "description": ("Could not install: "
                            + ", ".join(rep.failed)
                            + ". Modules requiring these tools will SKIP."),
            "remediation": ("Install manually: apt-get install <pkg>, "
                            "go install <pkg>@latest, or pip install <pkg>."),
        })
    findings.append({
        "title": "Toolchain readiness",
        "severity": "INFO",
        "target": "localhost",
        "description": (f"Present: {len(rep.present)}, "
                        f"Installed: {len(rep.installed)}, "
                        f"Failed: {len(rep.failed)}, "
                        f"apt_updated={rep.apt_updated}, "
                        f"venv={rep.venv_used}"),
    })
    return e.done(1, findings)


# =========================================================================== #
#  M02 — Passive OSINT                                                        #
# =========================================================================== #
async def m02_passive_osint(e: Engine) -> ModuleResult:
    if not e.scope.domains:
        return e.skip(2, "target is IP/CIDR — no domain to harvest", na=True)
    domain = next(iter(e.scope.domains))
    art = e.artifact_path(2, "subs.txt")
    rc, out, _ = await e.run_cmd(
        f"subfinder -d {domain} -silent -o {art}", 2, timeout=300)
    discovered = set()
    if art.exists():
        discovered = {l.strip() for l in art.read_text().splitlines() if l.strip()}
    # also amass passive
    art2 = e.artifact_path(2, "amass.txt")
    await e.run_cmd(f"amass enum -passive -d {domain} -o {art2}", 2, timeout=300)
    if art2.exists():
        discovered |= {l.strip() for l in art2.read_text().splitlines() if l.strip()}
    e.scope.domains.update(discovered)
    findings = [{
        "title": f"Subdomain discovered: {s}",
        "severity": "INFO", "target": s,
        "description": "Passive OSINT identified this asset.",
    } for s in sorted(discovered)[:200]]
    return e.done(2, findings, artifacts=[str(art), str(art2)])


# =========================================================================== #
#  M03 — Active DNS Brute                                                     #
# =========================================================================== #
async def m03_active_dns(e: Engine) -> ModuleResult:
    if not e.scope.domains:
        return e.skip(3, "no root domain", na=True)
    if e.evasion.profile.value == "STEALTH":
        return e.skip(3, "STEALTH profile disables active DNS brute")
    domain = next(d for d in e.scope.domains if "." in d)
    art = e.artifact_path(3, "brute.txt")
    wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if not Path(wordlist).exists():
        return e.skip(3, f"wordlist missing: {wordlist}")
    # ENH #6 — wildcard detection prevents thousands of false positives
    cmd = (f"puredns bruteforce {wordlist} {domain} "
           f"--rate-limit {e.evasion.rate_limit_qps} "
           f"--wildcard-tests 5 "
           f"--wildcard-batch 1000 "
           f"--write {art} -q")
    rc, out, _ = await e.run_cmd(cmd, 3, timeout=1800, soft_timeout=1500)
    new_subs = set()
    if art.exists():
        new_subs = {l.strip() for l in art.read_text().splitlines() if l.strip()}
    e.scope.domains.update(new_subs)
    findings = [{"title": f"Brute-forced subdomain: {s}", "severity": "INFO",
                 "target": s, "description": "Active DNS brute confirmed resolution."}
                for s in sorted(new_subs)[:200]]
    return e.done(3, findings, artifacts=[str(art)])


# =========================================================================== #
#  M04 — Reverse DNS + Geo                                                    #
# =========================================================================== #
async def m04_revdns(e: Engine) -> ModuleResult:
    if not e.scope.domains and not e.scope.ips:
        return e.skip(4, "no asset to resolve", na=True)
    # forward-resolve domains to IPs
    if e.scope.domains:
        dom_file = e.artifact_path(4, "domains.txt")
        dom_file.write_text("\n".join(e.scope.domains))
        ip_file = e.artifact_path(4, "ips.txt")
        await e.run_cmd(f"dnsx -l {dom_file} -a -resp-only -silent -o {ip_file}", 4, 180)
        if ip_file.exists():
            for ip in ip_file.read_text().splitlines():
                if ip.strip():
                    e.scope.ips.add(ip.strip())
    findings = [{"title": f"Resolved IP: {ip}", "severity": "INFO", "target": ip,
                 "description": "Asset resolution mapping."} for ip in sorted(e.scope.ips)]
    return e.done(4, findings)


# =========================================================================== #
#  M05 — Leaked Credentials                                                   #
# =========================================================================== #
async def m05_leaks(e: Engine) -> ModuleResult:
    if not e.scope.emails:
        return e.skip(5, "no emails harvested in M02")
    findings = []
    for email in list(e.scope.emails)[:25]:
        rc, out, _ = await e.run_cmd(f"h8mail -t {email} --loose", 5, 120)
        if "FOUND" in out.upper() or "BREACH" in out.upper():
            findings.append({
                "title": f"Credential exposure: {email}",
                "severity": "HIGH", "target": email, "cwe": "CWE-359",
                "description": "h8mail flagged this address in known breaches.",
                "remediation": "Force password rotation, enable MFA.",
            })
    return e.done(5, findings, cwes=["CWE-359"])


# =========================================================================== #
#  M06 — Live host discovery                                                  #
# =========================================================================== #
async def m06_live(e: Engine) -> ModuleResult:
    targets = list(e.scope.ips) + list(e.scope.cidrs)
    if not targets:
        return e.skip(6, "no IP / CIDR")
    tgt_file = e.artifact_path(6, "targets.txt")
    tgt_file.write_text("\n".join(targets))
    art = e.artifact_path(6, "live.txt")
    await e.run_cmd(f"nmap -sn -iL {tgt_file} -oG - | awk '/Up$/{{print $2}}' > {art}",
                    6, 600)
    live = set()
    if art.exists():
        live = {l.strip() for l in art.read_text().splitlines() if l.strip()}
    e.scope.live_hosts.update(live)
    findings = [{"title": f"Live host: {h}", "severity": "INFO", "target": h,
                 "description": "Host responded to ICMP/ARP discovery."}
                for h in sorted(live)]
    return e.done(6, findings, artifacts=[str(art)])


# =========================================================================== #
#  M07 — Port + service                                                       #
# =========================================================================== #
async def m07_portscan(e: Engine) -> ModuleResult:
    if not e.scope.live_hosts:
        return e.skip(7, "no live host from M06")
    findings = []
    for host in list(e.scope.live_hosts)[:50]:
        art = e.artifact_path(7, f"{host.replace(':','_')}.xml")
        rate = e.evasion.rate_limit_qps
        await e.run_cmd(
            f"nmap -sV -sC -p- --min-rate {rate} "
            f"-T{3 if e.evasion.profile.value=='STEALTH' else 4} "
            f"-oX {art} {host}",
            7, timeout=1800, soft_timeout=1500)
        ports = _parse_nmap_xml(art) if art.exists() else []
        e.scope.open_ports[host] = [p["port"] for p in ports]
        for p in ports:
            findings.append({
                "title": f"Open port {p['port']}/{p['proto']} ({p.get('service','')})",
                "severity": "INFO", "target": f"{host}:{p['port']}",
                "description": f"Service: {p.get('service','')} {p.get('version','')}",
            })
    return e.done(7, findings)


def _parse_nmap_xml(path: Path) -> list[dict]:
    """Tiny nmap XML parser — returns list of {port, proto, service, version}."""
    out = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.parse(path).getroot()
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            out.append({
                "port": int(port.get("portid", 0)),
                "proto": port.get("protocol", ""),
                "service": svc.get("name", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
    except Exception:
        pass
    return out


# =========================================================================== #
#  M08 — WAF detect                                                           #
# =========================================================================== #
async def m08_waf(e: Engine) -> ModuleResult:
    http_targets = [h for h, ports in e.scope.open_ports.items()
                    if any(p in ports for p in (80, 443, 8080, 8443))]
    if not http_targets:
        return e.skip(8, "no HTTP port open", na=True)
    findings = []
    for h in http_targets[:30]:
        rc, out, _ = await e.run_cmd(f"wafw00f http://{h} -a", 8, 60)
        m = re.search(r"is behind\s+(.+?)\s+WAF", out)
        if m:
            waf = m.group(1).strip()
            e.evasion.waf_detected = True
            findings.append({
                "title": f"WAF detected: {waf}",
                "severity": "INFO", "target": h,
                "description": f"wafw00f identified {waf}. Throttling enabled.",
            })
    if e.evasion.waf_detected:
        from core.evasion import EvasionProfile
        e.evasion.apply_profile(EvasionProfile.STEALTH)
    return e.done(8, findings)


# =========================================================================== #
#  M09 — SSL/TLS                                                              #
# =========================================================================== #
async def m09_tls(e: Engine) -> ModuleResult:
    tls_targets = []
    for h, ports in e.scope.open_ports.items():
        for p in ports:
            if p in (443, 8443, 993, 995, 465, 636, 989, 990):
                tls_targets.append((h, p))
    if not tls_targets:
        return e.skip(9, "no TLS port open", na=True)
    findings = []
    for h, p in tls_targets[:20]:
        art = e.artifact_path(9, f"{h}_{p}.json")
        await e.run_cmd(f"testssl.sh --jsonfile {art} --quiet {h}:{p}", 9, 600)
        if art.exists():
            try:
                data = json.loads(art.read_text())
                for item in data if isinstance(data, list) else []:
                    sev = item.get("severity", "INFO").upper()
                    if sev in ("HIGH", "CRITICAL", "MEDIUM"):
                        findings.append({
                            "title": item.get("id", "TLS issue"),
                            "severity": sev,
                            "target": f"{h}:{p}",
                            "cwe": "CWE-326",
                            "description": item.get("finding", ""),
                            "remediation": "Disable weak ciphers, enforce TLS 1.2+.",
                        })
            except Exception:
                pass
    return e.done(9, findings, cwes=["CWE-326"] if findings else [])


# =========================================================================== #
#  M10 — Net proto audit                                                      #
# =========================================================================== #
async def m10_netproto(e: Engine) -> ModuleResult:
    triggers = []
    for h, ports in e.scope.open_ports.items():
        for p in ports:
            if p in (53, 123, 161, 500, 161):
                triggers.append((h, p))
    if not triggers:
        return e.skip(10, "no SNMP/DNS/NTP/IKE port open", na=True)
    findings = []
    for h, p in triggers[:20]:
        script = {53: "dns-zone-transfer", 123: "ntp-monlist",
                  161: "snmp-info", 500: "ike-version"}.get(p, "banner")
        rc, out, _ = await e.run_cmd(
            f"nmap -sU -sV -p {p} --script {script} {h}", 10, 180)
        if "open" in out and len(out) > 200:
            findings.append({
                "title": f"{script} on {h}:{p}",
                "severity": "MEDIUM", "target": f"{h}:{p}",
                "description": out[:500],
                "remediation": "Restrict access to trusted networks.",
            })
    return e.done(10, findings)


# =========================================================================== #
#  M11 — SMB / RPC / NetBIOS                                                  #
# =========================================================================== #
async def m11_smb(e: Engine) -> ModuleResult:
    hosts = [h for h, ports in e.scope.open_ports.items()
             if 445 in ports or 139 in ports]
    if not hosts:
        return e.skip(11, "no SMB/NetBIOS port open", na=True)
    findings = []
    for h in hosts[:20]:
        rc, out, _ = await e.run_cmd(f"enum4linux-ng -A {h}", 11, 300)
        if "null session" in out.lower() or "shares" in out.lower():
            findings.append({
                "title": "SMB enumeration disclosure",
                "severity": "MEDIUM", "target": h, "cwe": "CWE-200",
                "description": "enum4linux-ng leaked user/share info.",
                "remediation": "Restrict null sessions, enforce SMB signing.",
            })
    return e.done(11, findings, cwes=["CWE-200"] if findings else [])


# =========================================================================== #
#  M12 — AD / Kerberos                                                        #
# =========================================================================== #
async def m12_ad(e: Engine) -> ModuleResult:
    ad_hosts = [h for h, ports in e.scope.open_ports.items()
                if any(p in ports for p in (88, 389, 636, 3268))]
    if not ad_hosts:
        return e.skip(12, "no AD/Kerberos port open", na=True)
    findings = []
    for h in ad_hosts[:10]:
        rc, out, _ = await e.run_cmd(f"netexec smb {h}", 12, 120)
        if "SMBv1" in out or "signing:False" in out:
            findings.append({
                "title": "AD host with weak SMB posture",
                "severity": "HIGH", "target": h, "cwe": "CWE-757",
                "description": out[:500],
                "remediation": "Enable SMB signing, disable SMBv1.",
            })
    return e.done(12, findings, cwes=["CWE-757"] if findings else [])


# =========================================================================== #
#  M13 — SSH / FTP / Telnet                                                   #
# =========================================================================== #
async def m13_remote(e: Engine) -> ModuleResult:
    targets = []
    for h, ports in e.scope.open_ports.items():
        for p in ports:
            if p in (21, 22, 23):
                targets.append((h, p))
    if not targets:
        return e.skip(13, "no SSH/FTP/Telnet port open", na=True)
    findings = []
    for h, p in targets[:20]:
        if p == 22:
            rc, out, _ = await e.run_cmd(f"ssh-audit {h}", 13, 60)
            if "[fail]" in out or "[warn]" in out:
                findings.append({
                    "title": "Weak SSH configuration",
                    "severity": "MEDIUM", "target": f"{h}:22", "cwe": "CWE-326",
                    "description": out[:600],
                    "remediation": "Disable weak kex/cipher/MAC algorithms.",
                })
        elif p == 23:
            findings.append({
                "title": "Telnet exposed", "severity": "HIGH",
                "target": f"{h}:23", "cwe": "CWE-319",
                "description": "Cleartext protocol exposed.",
                "remediation": "Replace with SSH.",
            })
    return e.done(13, findings)


# =========================================================================== #
#  M14 — DB discovery                                                         #
# =========================================================================== #
async def m14_db(e: Engine) -> ModuleResult:
    db_ports = {1433, 3306, 5432, 27017, 1521, 6379, 9200}
    targets = [(h, p) for h, ports in e.scope.open_ports.items()
               for p in ports if p in db_ports]
    if not targets:
        return e.skip(14, "no DB port open", na=True)
    findings = [{"title": f"DB instance: port {p}", "severity": "MEDIUM",
                 "target": f"{h}:{p}", "cwe": "CWE-200",
                 "description": "Database port exposed to scope.",
                 "remediation": "Restrict to application tier only."}
                for h, p in targets]
    return e.done(14, findings)


# =========================================================================== #
#  M15 — Web HTTP filter                                                      #
# =========================================================================== #
async def m15_httpx(e: Engine) -> ModuleResult:
    seeds = []
    for h, ports in e.scope.open_ports.items():
        for p in ports:
            if p in (80, 443, 8080, 8443, 8000, 8888, 5000):
                scheme = "https" if p in (443, 8443) else "http"
                seeds.append(f"{scheme}://{h}:{p}")
    for d in e.scope.domains:
        seeds.append(f"https://{d}")
    if not seeds:
        return e.skip(15, "no candidate HTTP endpoint", na=True)
    tgt_file = e.artifact_path(15, "seeds.txt")
    tgt_file.write_text("\n".join(set(seeds)))
    out_file = e.artifact_path(15, "live.json")
    await e.run_cmd(
        f"httpx -l {tgt_file} -json -title -tech-detect -status-code -silent "
        f"-o {out_file}", 15, 600)
    findings = []
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            try:
                row = json.loads(line)
            except Exception:
                continue
            url = row.get("url")
            if not url:
                continue
            e.scope.http_urls.add(url)
            e.see(url)  # ENH #7 — seed global dedup set
            if row.get("tech"):
                e.scope.tech_stack[url] = row["tech"]
            findings.append({
                "title": f"Live HTTP: {url}",
                "severity": "INFO", "target": url,
                "description": f"Status {row.get('status_code')} | "
                               f"Tech: {','.join(row.get('tech', []))}",
            })
    return e.done(15, findings)


# =========================================================================== #
#  M16 — Web fingerprint                                                      #
# =========================================================================== #
async def m16_fingerprint(e: Engine) -> ModuleResult:
    if not e.scope.http_urls:
        return e.skip(16, "no live URL")
    findings = []
    for url in list(e.scope.http_urls)[:30]:
        rc, out, _ = await e.run_cmd(f"whatweb --log-json=- {url}", 16, 60)
        try:
            data = json.loads(out.splitlines()[0]) if out.strip() else {}
            plugins = list(data.get("plugins", {}).keys())
            if plugins:
                e.scope.tech_stack.setdefault(url, []).extend(plugins)
                findings.append({
                    "title": "Web stack identified",
                    "severity": "INFO", "target": url,
                    "description": "Plugins: " + ", ".join(plugins[:20]),
                })
        except Exception:
            pass
    return e.done(16, findings)


# =========================================================================== #
#  M17 — Dir / file fuzz                                                      #
# =========================================================================== #
async def m17_dirfuzz(e: Engine) -> ModuleResult:
    if not e.scope.http_urls:
        return e.skip(17, "no live URL", na=True)
    findings = []
    for url in list(e.scope.http_urls)[:10]:
        # ENH #10 tech-stack gating — skip dir-fuzz on schema'd APIs
        techs = " ".join(e.scope.tech_stack.get(url, [])).lower()
        if any(k in techs for k in ("api", "graphql", "swagger", "openapi")):
            continue  # M19 handles API surface
        if url in e.scope.api_schemas:
            continue
        art = e.artifact_path(17, f"ferox_{abs(hash(url))}.json")
        await e.run_cmd(
            f"feroxbuster -u {url} -t {e.evasion.max_threads} -d 2 "
            f"--json --silent -o {art}", 17, 900)
        if art.exists():
            for line in art.read_text().splitlines():
                try:
                    row = json.loads(line)
                    if row.get("type") == "response" and row.get("status") in (200, 401, 403):
                        findings.append({
                            "title": f"Path found ({row['status']})",
                            "severity": "LOW" if row['status'] == 200 else "INFO",
                            "target": row.get("url", ""),
                            "description": f"Size: {row.get('content_length','?')}",
                        })
                except Exception:
                    pass
    return e.done(17, findings)


# =========================================================================== #
#  M18 — Param fuzz                                                           #
# =========================================================================== #
async def m18_paramfuzz(e: Engine) -> ModuleResult:
    if not e.scope.http_urls:
        return e.skip(18, "no live URL", na=True)
    findings = []
    for url in list(e.scope.http_urls)[:10]:
        rc, out, _ = await e.run_cmd(f"arjun -u {url} -q --stable", 18, 300)
        params = re.findall(r"Parameters\s*:\s*([\w,\s]+)", out)
        if params:
            plist = [p.strip() for p in params[0].split(",") if p.strip()]
            e.scope.discovered_params[url] = plist
            findings.append({
                "title": f"Hidden parameters: {', '.join(plist[:20])}",
                "severity": "LOW", "target": url,
                "description": "Arjun confirmed reflective parameters.",
            })
    return e.done(18, findings)


# =========================================================================== #
#  M19 — API audit                                                            #
# =========================================================================== #
async def m19_api(e: Engine) -> ModuleResult:
    api_urls = []
    for url in e.scope.http_urls:
        if any(k in url.lower() for k in ("api", "graphql", "swagger", "openapi")):
            api_urls.append(url)
    if not api_urls:
        return e.skip(19, "no API surface detected", na=True)
    findings = []
    for url in api_urls[:10]:
        for path in ("/swagger.json", "/openapi.json", "/graphql", "/api-docs"):
            rc, out, _ = await e.run_cmd(f"curl -sk -o /dev/null -w '%{{http_code}}' {url}{path}",
                                          19, 30)
            if out.strip().startswith("2"):
                e.scope.api_schemas[url + path] = "exposed"
                findings.append({
                    "title": f"API schema exposed: {path}",
                    "severity": "MEDIUM", "target": url + path,
                    "cwe": "CWE-200",
                    "description": "Public schema discoverable.",
                    "remediation": "Authenticate or remove schema endpoints.",
                })
    return e.done(19, findings, cwes=["CWE-200"] if findings else [])


# =========================================================================== #
#  M20 — XSS                                                                  #
# =========================================================================== #
async def m20_xss(e: Engine) -> ModuleResult:
    if not e.scope.discovered_params:
        return e.skip(20, "no parameter sink from M18", na=True)
    findings = []
    for url, params in list(e.scope.discovered_params.items())[:10]:
        q = "&".join(f"{p}=FUZZ" for p in params[:3])
        rc, out, _ = await e.run_cmd(f"dalfox url '{url}?{q}' --silence", 20, 300)
        if "POC" in out or "VULN" in out:
            findings.append({
                "title": "Reflected XSS confirmed",
                "severity": "HIGH", "target": url,
                "cwe": "CWE-79", "cvss": "6.1",
                "description": out[:500],
                "remediation": "Context-aware output encoding, CSP.",
            })
    return e.done(20, findings, cwes=["CWE-79"] if findings else [])


# =========================================================================== #
#  M21 — SQLi                                                                 #
# =========================================================================== #
async def m21_sqli(e: Engine) -> ModuleResult:
    if not e.scope.discovered_params:
        return e.skip(21, "no parameter sink from M18", na=True)
    findings = []
    for url, params in list(e.scope.discovered_params.items())[:5]:
        q = "&".join(f"{p}=1" for p in params[:3])
        target = f"{url}?{q}"
        rc, out, _ = await e.run_cmd(
            f"sqlmap -u '{target}' --batch --level=2 --risk=1 --smart "
            f"--timeout=15 --retries=1", 21, 600)
        if "is vulnerable" in out.lower() or "parameter:" in out.lower():
            findings.append({
                "title": "SQL Injection confirmed",
                "severity": "CRITICAL", "target": target,
                "cve": None, "cwe": "CWE-89", "cvss": "9.8",
                "description": "sqlmap verified injection vector.",
                "remediation": "Parameterized queries / ORM; reject untrusted input.",
            })
    return e.done(21, findings, cwes=["CWE-89"] if findings else [])


# =========================================================================== #
#  M22 — SSRF / LFI / RFI                                                     #
# =========================================================================== #
async def m22_ssrf(e: Engine) -> ModuleResult:
    if not e.scope.discovered_params:
        return e.skip(22, "no parameter accepting URL/path", na=True)
    findings = []
    for url, params in list(e.scope.discovered_params.items())[:5]:
        for p in params[:3]:
            payload = "../../../../etc/passwd"
            rc, out, _ = await e.run_cmd(
                f"curl -sk '{url}?{p}={payload}' | head -c 1000", 22, 30)
            if "root:x:0:0" in out:
                findings.append({
                    "title": "Local File Inclusion",
                    "severity": "CRITICAL", "target": f"{url}?{p}",
                    "cwe": "CWE-22", "cvss": "9.1",
                    "description": "/etc/passwd disclosed.",
                    "remediation": "Reject path traversal, allowlist.",
                })
    return e.done(22, findings, cwes=["CWE-22"] if findings else [])


# =========================================================================== #
#  M23 — CMDi / SSTI                                                          #
# =========================================================================== #
async def m23_cmdi(e: Engine) -> ModuleResult:
    if not e.scope.discovered_params:
        return e.skip(23, "no param to inject", na=True)
    findings = []
    for url, params in list(e.scope.discovered_params.items())[:3]:
        rc, out, _ = await e.run_cmd(
            f"commix --url='{url}?{params[0]}=1' --batch --random-agent", 23, 600)
        if "is vulnerable" in out.lower():
            findings.append({
                "title": "OS command injection",
                "severity": "CRITICAL", "target": url,
                "cwe": "CWE-78", "cvss": "9.8",
                "description": "commix confirmed shell execution.",
                "remediation": "Strict input validation, sandboxed exec.",
            })
    return e.done(23, findings, cwes=["CWE-78"] if findings else [])


# =========================================================================== #
#  M24 — CMS                                                                  #
# =========================================================================== #
async def m24_cms(e: Engine) -> ModuleResult:
    cms_targets = []
    for url, techs in e.scope.tech_stack.items():
        joined = " ".join(techs).lower()
        if "wordpress" in joined: cms_targets.append((url, "wp"))
        elif "joomla" in joined: cms_targets.append((url, "joomla"))
        elif "drupal" in joined: cms_targets.append((url, "drupal"))
    if not cms_targets:
        return e.skip(24, "no recognised CMS in tech stack", na=True)
    findings = []
    for url, cms in cms_targets[:5]:
        if cms == "wp":
            rc, out, _ = await e.run_cmd(
                f"wpscan --url {url} --no-banner --random-user-agent "
                f"--disable-tls-checks", 24, 600)
        elif cms == "joomla":
            rc, out, _ = await e.run_cmd(f"joomscan -u {url}", 24, 600)
        else:
            rc, out, _ = await e.run_cmd(f"droopescan scan drupal -u {url}", 24, 600)
        for cve in re.findall(r"CVE-\d{4}-\d+", out):
            findings.append({
                "title": f"{cms.upper()} vulnerability {cve}",
                "severity": "HIGH", "target": url, "cve": cve,
                "description": "CMS scanner flagged known CVE.",
                "remediation": "Patch CMS core + plugins immediately.",
            })
    return e.done(24, findings, cves=list({f["cve"] for f in findings if f.get("cve")}))


# =========================================================================== #
#  M25 — AuthN / Session                                                      #
# =========================================================================== #
async def m25_auth(e: Engine) -> ModuleResult:
    if not e.scope.http_urls:
        return e.skip(25, "no live URL", na=True)
    findings = []
    for url in list(e.scope.http_urls)[:15]:
        rc, out, _ = await e.run_cmd(
            f"curl -sk -I {url}", 25, 30)
        if "Set-Cookie" in out:
            cookie_line = next((l for l in out.splitlines() if l.startswith("Set-Cookie")), "")
            issues = []
            if "Secure" not in cookie_line: issues.append("Missing Secure")
            if "HttpOnly" not in cookie_line: issues.append("Missing HttpOnly")
            if "SameSite" not in cookie_line: issues.append("Missing SameSite")
            if issues:
                findings.append({
                    "title": "Insecure session cookie",
                    "severity": "MEDIUM", "target": url,
                    "cwe": "CWE-614",
                    "description": "; ".join(issues),
                    "remediation": "Set Secure, HttpOnly, SameSite=Lax/Strict.",
                })
    return e.done(25, findings, cwes=["CWE-614"] if findings else [])


# =========================================================================== #
#  M26 — Subdomain takeover                                                   #
# =========================================================================== #
async def m26_takeover(e: Engine) -> ModuleResult:
    if not e.scope.domains:
        return e.skip(26, "no domain", na=True)
    dom_file = e.artifact_path(26, "all_subs.txt")
    dom_file.write_text("\n".join(e.scope.domains))
    rc, out, _ = await e.run_cmd(f"subzy run --targets {dom_file} --concurrency 10",
                                  26, 600)
    findings = []
    for line in out.splitlines():
        if "VULNERABLE" in line.upper():
            sub = line.split()[0] if line.split() else "unknown"
            findings.append({
                "title": f"Subdomain takeover possible: {sub}",
                "severity": "HIGH", "target": sub,
                "cwe": "CWE-350",
                "description": line,
                "remediation": "Remove dangling DNS record or reclaim resource.",
            })
    return e.done(26, findings, cwes=["CWE-350"] if findings else [])


# =========================================================================== #
#  M27 — Nuclei                                                               #
# =========================================================================== #
async def m27_nuclei(e: Engine) -> ModuleResult:
    if not e.scope.http_urls:
        return e.skip(27, "no live URL", na=True)
    tgt = e.artifact_path(27, "targets.txt")
    tgt.write_text("\n".join(e.scope.http_urls))
    out_file = e.artifact_path(27, "nuclei.jsonl")
    # `-jsonl` for nuclei v3+; older versions need `-json`. Try v3 first.
    await e.run_cmd(
        f"nuclei -l {tgt} -severity low,medium,high,critical -as "
        f"-jsonl -o {out_file} -silent -update-templates",
        27, timeout=2400, soft_timeout=2100)
    findings = []
    cves = set()
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            try:
                row = json.loads(line)
                info = row.get("info", {})
                cls = info.get("classification", {})
                cve_id = (cls.get("cve-id") or [None])[0] if isinstance(cls.get("cve-id"), list) else cls.get("cve-id")
                if cve_id: cves.add(cve_id)
                findings.append({
                    "title": info.get("name", "nuclei finding"),
                    "severity": (info.get("severity") or "INFO").upper(),
                    "target": row.get("matched-at", ""),
                    "cve": cve_id,
                    "cwe": (cls.get("cwe-id") or [None])[0] if isinstance(cls.get("cwe-id"), list) else cls.get("cwe-id"),
                    "cvss": cls.get("cvss-score"),
                    "description": info.get("description", ""),
                    "remediation": info.get("remediation", ""),
                })
            except Exception:
                pass
    return e.done(27, findings, cves=list(cves))


# =========================================================================== #
#  M28 — Credential brute (safe micro-wordlist)                               #
# =========================================================================== #
async def m28_brute(e: Engine) -> ModuleResult:
    if e.scope.no_brute or e.evasion.profile.value == "STEALTH":
        return e.skip(28, "brute disabled by scope/profile")
    targets = []
    for h, ports in e.scope.open_ports.items():
        for p in ports:
            if p in (21, 22, 3389):
                targets.append((h, p, {21: "ftp", 22: "ssh", 3389: "rdp"}[p]))
    if not targets:
        return e.skip(28, "no auth proto open", na=True)
    micro_users = e.artifact_path(28, "users.txt")
    micro_pass = e.artifact_path(28, "pass.txt")
    micro_users.write_text("admin\nroot\nuser\n")
    micro_pass.write_text("admin\npassword\n123456\n")
    findings = []
    for h, p, svc in targets[:5]:
        rc, out, _ = await e.run_cmd(
            f"hydra -L {micro_users} -P {micro_pass} -t 2 -f -o "
            f"{e.artifact_path(28, f'{h}_{p}.txt')} {svc}://{h}:{p}",
            28, 300)
        if "login:" in out and "password:" in out:
            findings.append({
                "title": f"Weak credentials on {svc}",
                "severity": "CRITICAL", "target": f"{h}:{p}",
                "cwe": "CWE-521", "cvss": "9.8",
                "description": "Default/weak credential pair accepted.",
                "remediation": "Enforce strong password policy + MFA + lockout.",
            })
    return e.done(28, findings, cwes=["CWE-521"] if findings else [])


# =========================================================================== #
#  M29 — Cloud storage                                                        #
# =========================================================================== #
async def m29_cloud(e: Engine) -> ModuleResult:
    if e.scope.is_internal:
        return e.skip(29, "target is RFC1918 — cloud module N/A", na=True)
    if not e.scope.org_name:
        return e.skip(29, "no org name to seed bucket search", na=True)
    findings = []
    rc, out, _ = await e.run_cmd(
        f"s3scanner scan --bucket {e.scope.org_name}", 29, 300)
    if "exists" in out.lower():
        findings.append({
            "title": f"S3 bucket exists: {e.scope.org_name}",
            "severity": "MEDIUM", "target": e.scope.org_name,
            "cwe": "CWE-284",
            "description": out[:500],
            "remediation": "Audit bucket ACLs, block public access.",
        })
    return e.done(29, findings, cwes=["CWE-284"] if findings else [])


# =========================================================================== #
#  M30 — Container                                                            #
# =========================================================================== #
async def m30_container(e: Engine) -> ModuleResult:
    container_ports = {2375, 2376, 10250, 10255, 6443, 8443}
    found = [(h, p) for h, ports in e.scope.open_ports.items()
             for p in ports if p in container_ports]
    if not found:
        return e.skip(30, "no container port open", na=True)
    findings = []
    for h, p in found[:10]:
        if p == 2375:
            findings.append({
                "title": "Docker API exposed unauthenticated",
                "severity": "CRITICAL", "target": f"{h}:2375",
                "cwe": "CWE-306", "cvss": "10.0",
                "description": "Port 2375 (Docker API) reachable.",
                "remediation": "Bind to localhost, require TLS auth on 2376.",
            })
        if p in (10250, 10255):
            findings.append({
                "title": "Kubelet API exposed",
                "severity": "HIGH", "target": f"{h}:{p}", "cwe": "CWE-306",
                "description": "Kubelet read-only / privileged port open.",
                "remediation": "Disable anonymous auth, restrict by network.",
            })
    return e.done(30, findings, cwes=["CWE-306"] if findings else [])


# =========================================================================== #
#  M31 — CI/CD / Git exposure                                                 #
# =========================================================================== #
async def m31_cicd(e: Engine) -> ModuleResult:
    if not e.scope.http_urls:
        return e.skip(31, "no live URL", na=True)
    findings = []
    for url in list(e.scope.http_urls)[:30]:
        rc, out, _ = await e.run_cmd(
            f"curl -sk -o /dev/null -w '%{{http_code}}' {url}/.git/HEAD", 31, 30)
        if out.strip() == "200":
            findings.append({
                "title": "Exposed .git directory",
                "severity": "HIGH", "target": f"{url}/.git/",
                "cwe": "CWE-538", "cvss": "7.5",
                "description": "Public .git enables source code disclosure.",
                "remediation": "Deny /.git/ at web server level.",
            })
    return e.done(31, findings, cwes=["CWE-538"] if findings else [])


# =========================================================================== #
#  M32 — IoT / firmware                                                       #
# =========================================================================== #
async def m32_iot(e: Engine) -> ModuleResult:
    iot_ports = {1883, 8883, 5683, 502, 47808}
    targets = [(h, p) for h, ports in e.scope.open_ports.items()
               for p in ports if p in iot_ports]
    if not targets:
        return e.skip(32, "no IoT protocol port", na=True)
    findings = []
    for h, p in targets[:10]:
        proto = {1883: "MQTT", 8883: "MQTT-TLS", 5683: "CoAP",
                 502: "Modbus", 47808: "BACnet"}.get(p, "?")
        findings.append({
            "title": f"{proto} exposed",
            "severity": "MEDIUM", "target": f"{h}:{p}", "cwe": "CWE-319",
            "description": f"{proto} reachable — often unauthenticated.",
            "remediation": "Network-isolate IoT VLAN, enforce auth/TLS.",
        })
    return e.done(32, findings, cwes=["CWE-319"] if findings else [])


# =========================================================================== #
#  M33 — Evasion validation                                                   #
# =========================================================================== #
async def m33_evasion(e: Engine) -> ModuleResult:
    findings = [{
        "title": "Evasion telemetry snapshot",
        "severity": "INFO", "target": e.scope.raw_target,
        "description": (f"profile={e.evasion.profile.value} "
                        f"delay={e.evasion.base_delay}s "
                        f"qps={e.evasion.rate_limit_qps} "
                        f"waf={e.evasion.waf_detected} "
                        f"429s={e.evasion.consecutive_429} "
                        f"403s={e.evasion.consecutive_403}"),
    }]
    return e.done(33, findings)


# =========================================================================== #
#  M34 — Post-exploit simulation                                              #
# =========================================================================== #
async def m34_postexploit(e: Engine) -> ModuleResult:
    artifact = Path("./post_exploit_artifact.txt")
    if not artifact.exists():
        return e.skip(34, "no local artifact supplied for post-ex parsing", na=True)
    text = artifact.read_text(errors="replace")
    findings = []
    if re.search(r"NOPASSWD", text):
        findings.append({
            "title": "Sudo NOPASSWD detected",
            "severity": "HIGH", "target": "localhost", "cwe": "CWE-269",
            "description": "Misconfigured sudoers permits privilege escalation.",
            "remediation": "Require password for sudo, audit /etc/sudoers.",
        })
    return e.done(34, findings)


# =========================================================================== #
#  M35 — Consolidation                                                        #
# =========================================================================== #
async def m35_consolidate(e: Engine) -> ModuleResult:
    total = sum(len(r.findings) for r in e.results.values())
    cves = sorted({c for r in e.results.values() for c in r.cves})
    cwes = sorted({c for r in e.results.values() for c in r.cwes})
    findings = [{
        "title": "Consolidation summary",
        "severity": "INFO", "target": e.scope.raw_target,
        "description": (f"Modules COMPLETED: "
                        f"{sum(1 for r in e.results.values() if r.state.value=='COMPLETED')}; "
                        f"SKIPPED/N-A: "
                        f"{sum(1 for r in e.results.values() if r.state.value in ('SKIPPED','NOT_APPLICABLE'))}; "
                        f"Total raw findings: {total}; "
                        f"Unique CVEs: {len(cves)}; Unique CWEs: {len(cwes)}."),
    }]
    return e.done(35, findings, cves=cves, cwes=cwes)


# =========================================================================== #
#  Registry                                                                    #
# =========================================================================== #
def build_module_list():
    return [
        (1,  "Bootstrap",                 m01_bootstrap),
        (2,  "Passive OSINT",             m02_passive_osint),
        (3,  "Active Subdomain",          m03_active_dns),
        (4,  "Reverse DNS / Geo",         m04_revdns),
        (5,  "Threat Intel / Leaks",      m05_leaks),
        (6,  "Live Hosts",                m06_live),
        (7,  "Port + Service",            m07_portscan),
        (8,  "WAF / IDS Detect",          m08_waf),
        (9,  "SSL / TLS Audit",           m09_tls),
        (10, "Network Protocol Audit",    m10_netproto),
        (11, "SMB / RPC / NetBIOS",       m11_smb),
        (12, "AD / Kerberos",             m12_ad),
        (13, "SSH / FTP / Telnet",        m13_remote),
        (14, "DB Discovery",              m14_db),
        (15, "Web HTTP Filter",           m15_httpx),
        (16, "Web Fingerprint",           m16_fingerprint),
        (17, "Dir / File Fuzz",           m17_dirfuzz),
        (18, "Param Fuzz",                m18_paramfuzz),
        (19, "API Audit",                 m19_api),
        (20, "XSS",                       m20_xss),
        (21, "SQLi",                      m21_sqli),
        (22, "SSRF / LFI / RFI",          m22_ssrf),
        (23, "CMDi / SSTI",               m23_cmdi),
        (24, "CMS Audit",                 m24_cms),
        (25, "AuthN / Session",           m25_auth),
        (26, "Subdomain Takeover",        m26_takeover),
        (27, "Nuclei Templates",          m27_nuclei),
        (28, "Credential Brute",          m28_brute),
        (29, "Cloud Storage",             m29_cloud),
        (30, "Container",                 m30_container),
        (31, "CI/CD / Git",               m31_cicd),
        (32, "IoT / Firmware",            m32_iot),
        (33, "Evasion Validation",        m33_evasion),
        (34, "Post-Exploit Sim",          m34_postexploit),
        (35, "Consolidation",             m35_consolidate),
    ]
