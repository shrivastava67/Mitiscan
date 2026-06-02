"""Conditional reporting engine.

Reads engine.results, drops any module that is SKIPPED / NOT_APPLICABLE /
FAILED / COMPLETED-with-no-findings. Renders NIST SP 800-115 + OWASP styled
HTML + Markdown. No empty section headers ever reach the final document.
"""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .result import ModuleResult, State


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Reporter:
    def __init__(self, results: dict[int, ModuleResult], out_dir: Path,
                 target: str, run_id: str, template_dir: Path) -> None:
        self.results = results
        self.out_dir = out_dir
        self.target = target
        self.run_id = run_id
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True, lstrip_blocks=True,
        )

    # ---------- conditional filter ---------- #
    def _renderable_modules(self) -> list[ModuleResult]:
        """Drop anything without findings. THIS is the conditional gate."""
        keep = [r for r in self.results.values() if r.has_renderable]
        keep.sort(key=lambda r: r.module_id)
        return keep

    def _aggregate(self) -> dict:
        rendered = self._renderable_modules()
        all_findings: list[dict] = []
        cve_set: set[str] = set()
        cwe_set: set[str] = set()
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in rendered:
            cve_set.update(r.cves)
            cwe_set.update(r.cwes)
            for f in r.findings:
                sev = (f.get("severity") or "INFO").upper()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                all_findings.append({**f, "_module": r.name, "_module_id": r.module_id})
        # ENH #9 — dedup by normalized title + target. Lower-case, strip
        # punctuation/whitespace so "Reflected XSS" and "reflected-xss" collapse.
        import re as _re
        def _norm(s: str | None) -> str:
            return _re.sub(r"[^a-z0-9]+", "", (s or "").lower())
        seen: set[tuple[str, str, str]] = set()
        deduped: list[dict] = []
        for f in all_findings:
            k = (_norm(f.get("title")), _norm(f.get("target")),
                 (f.get("severity") or "INFO").upper())
            if k in seen:
                continue
            seen.add(k)
            deduped.append(f)
        deduped.sort(key=lambda f: SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 9))

        # state matrix — every module shown w/ status (for executive table)
        state_matrix = []
        for mid in sorted(self.results.keys()):
            r = self.results[mid]
            state_matrix.append({
                "id": mid, "name": r.name, "state": r.state.value,
                "findings": len(r.findings), "reason": r.skip_reason or "",
                "duration": r.duration_sec,
            })
        return {
            "rendered_modules": rendered,
            "all_findings": deduped,
            "cve_list": sorted(cve_set),
            "cwe_list": sorted(cwe_set),
            "severity_counts": sev_counts,
            "state_matrix": state_matrix,
            "target": self.target,
            "run_id": self.run_id,
            "generated_at": dt.datetime.utcnow().isoformat() + "Z",
            "standard": "NIST SP 800-115 / OWASP Testing Guide v4.2",
        }

    # ---------- output ---------- #
    def render_html(self) -> Path:
        ctx = self._aggregate()
        html = self.env.get_template("report.html.j2").render(**ctx)
        path = self.out_dir / "report.html"
        path.write_text(html, encoding="utf-8")
        return path

    def render_markdown(self) -> Path:
        ctx = self._aggregate()
        lines: list[str] = []
        lines.append(f"# Mitiscan Report — `{ctx['target']}`")
        lines.append("")
        lines.append(f"- **Run ID:** `{ctx['run_id']}`")
        lines.append(f"- **Generated:** {ctx['generated_at']}")
        lines.append(f"- **Standard:** {ctx['standard']}")
        lines.append("")
        lines.append("## Executive Summary")
        s = ctx["severity_counts"]
        lines.append(f"- Critical: **{s['CRITICAL']}** | High: **{s['HIGH']}** | "
                     f"Medium: **{s['MEDIUM']}** | Low: **{s['LOW']}** | Info: **{s['INFO']}**")
        if ctx["cve_list"]:
            lines.append(f"- CVEs referenced: {', '.join(ctx['cve_list'])}")
        if ctx["cwe_list"]:
            lines.append(f"- CWEs referenced: {', '.join(ctx['cwe_list'])}")
        lines.append("")
        # CONDITIONAL: iterate only renderable modules. No blank headers.
        for r in ctx["rendered_modules"]:
            lines.append(f"## M{r.module_id:02d} — {r.name}")
            lines.append(f"_State: {r.state.value} · Duration: {r.duration_sec}s · "
                         f"Findings: {len(r.findings)}_")
            lines.append("")
            for f in r.findings:
                sev = (f.get("severity") or "INFO").upper()
                lines.append(f"### [{sev}] {f.get('title','(no title)')}")
                if f.get("target"):
                    lines.append(f"- **Target:** `{f['target']}`")
                if f.get("cve"):
                    lines.append(f"- **CVE:** {f['cve']}")
                if f.get("cwe"):
                    lines.append(f"- **CWE:** {f['cwe']}")
                if f.get("cvss"):
                    lines.append(f"- **CVSS v3.1:** {f['cvss']}")
                if f.get("description"):
                    lines.append("")
                    lines.append(f["description"])
                if f.get("remediation"):
                    lines.append("")
                    lines.append(f"**Remediation:** {f['remediation']}")
                lines.append("")
        path = self.out_dir / "report.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def render_json(self) -> Path:
        ctx = self._aggregate()
        serial = {
            **{k: v for k, v in ctx.items() if k != "rendered_modules"},
            "rendered_modules": [asdict(r) for r in ctx["rendered_modules"]],
        }
        path = self.out_dir / "report.json"
        path.write_text(json.dumps(serial, default=str, indent=2), encoding="utf-8")
        return path

    def render_pdf(self) -> Path | None:
        """ENH #14 — HTML → PDF via weasyprint. Returns None if dep missing."""
        try:
            from weasyprint import HTML  # type: ignore
        except Exception:
            return None
        html_path = self.out_dir / "report.html"
        if not html_path.exists():
            self.render_html()
        pdf_path = self.out_dir / "report.pdf"
        try:
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            return pdf_path
        except Exception:
            return None

    def render_all(self) -> dict[str, Path]:
        out = {
            "html": self.render_html(),
            "md": self.render_markdown(),
            "json": self.render_json(),
        }
        pdf = self.render_pdf()
        if pdf:
            out["pdf"] = pdf
        return out
