"""
threattracer.cli.output
~~~~~~~~~~~~~~~~~~~~~~~~
Rich-based output: tables, detail panels, asset scan results, JSON, CSV.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from typing import List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from threattracer.core.scanner import ScanResult
from threattracer.utils.models import (
    AssetScanResult,
    CVERecord,
    CPEMatch,
    Severity,
)

console = Console(stderr=False)
err_console = Console(stderr=True)

BANNER = r"""[bold cyan]
  _______ _                    _ _______                      
 |__   __| |                  | |__   __|                     
    | |  | |__  _ __ ___  __ _| |_ | |_ __ __ _  ___ ___ _ __ 
    | |  | '_ \| '__/ _ \/ _` | __|| | '__/ _` |/ __/ _ \ '__|
    | |  | | | | | |  __/ (_| | |_ | | | | (_| | (_|  __/ |   
    |_|  |_| |_|_|  \___|\__,_|\__||_|_|  \__,_|\___\___|_|[/bold cyan][dim]  v4.1[/dim]
[italic dim]   A tool to identify CVEs, exploits & PoCs by component name, CPE or CVE ID[/italic dim]
[italic dim]          -+ Hunt for 0Days, PoCs and weaponised exploits +-[/italic dim]
[dim]   Authors:  @FR13ND0x7F  @0xCaretaker  @meppohak5[/dim]
"""

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "green",
    Severity.NONE:     "dim",
    Severity.UNKNOWN:  "dim",
}
_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🟢",
    Severity.NONE:     "⚪",
    Severity.UNKNOWN:  "❓",
}


def print_banner() -> None:
    console.print(BANNER)


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=err_console,
        transient=True,
    )


# ── CPE table ─────────────────────────────────────────────────────────────

def print_cpe_table(cpe_matches: List[CPEMatch]) -> None:
    t = Table(title="[bold]CPE Matches[/bold]", box=box.ROUNDED, show_lines=True)
    t.add_column("#", style="dim", width=3)
    t.add_column("CPE Name", style="cyan")
    t.add_column("Title", style="white")
    t.add_column("Score", justify="right", width=7)
    for i, m in enumerate(cpe_matches, 1):
        sc = m.match_score
        style = "green" if sc >= 70 else "yellow" if sc >= 40 else "red"
        t.add_row(str(i), m.cpe_name, m.title or "", f"[{style}]{sc:.0f}[/{style}]")
    console.print(t)


# ── CVE summary table ──────────────────────────────────────────────────────

def print_cve_table(records: List[CVERecord], show_description: bool = False) -> None:
    t = Table(
        title=f"[bold]CVE Results[/bold]  ({len(records)} found)",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    t.add_column("Sev",       width=4,  no_wrap=True)
    t.add_column("CVE ID",    style="bold", no_wrap=True, width=18)
    t.add_column("CVSS",      justify="center", width=6)
    t.add_column("EPSS%",     justify="center", width=7)
    t.add_column("AV",        width=9)   # Attack Vector abbrev
    t.add_column("PR",        width=5)   # Privileges Required abbrev
    t.add_column("EDB",       width=4,  justify="center")
    t.add_column("PoC",       width=4,  justify="center")
    t.add_column("Nuclei",    width=7,  justify="center")
    t.add_column("MSF",       width=4,  justify="center")
    t.add_column("KEV",       width=4,  justify="center")
    t.add_column("Published", width=11)

    for r in records:
        sev   = r.severity
        style = _SEV_STYLE.get(sev, "")
        emoji = _SEV_EMOJI.get(sev, "")

        cvss_str  = f"{r.cvss_score:.1f}" if r.cvss_score else "N/A"
        epss_str  = f"{r.epss_score*100:.1f}%" if r.epss_score is not None else "N/A"
        av        = _abbrev_av((r.cvss.attack_vector or "") if r.cvss else "")
        pr        = _abbrev_pr((r.cvss.privileges_required or "") if r.cvss else "")
        published = (r.published or "")[:10]

        edb_flag    = _tick(r.exploits, "green")
        poc_flag    = _tick(r.pocs, "cyan")
        nuclei_flag = _tick(r.nuclei_templates, "magenta")
        msf_flag    = _tick(r.msf_modules, "red")
        kev_flag    = "[bold red]🔥[/bold red]" if r.in_kev else "[dim]✗[/dim]"

        t.add_row(
            f"[{style}]{emoji}[/{style}]",
            f"[{style}]{r.cve_id}[/{style}]",
            f"[{style}]{cvss_str}[/{style}]",
            epss_str,
            av, pr,
            edb_flag, poc_flag, nuclei_flag, msf_flag, kev_flag,
            published,
        )

    console.print(t)
    _print_legend()

    if show_description:
        for r in records:
            print_cve_detail(r)


def _abbrev_av(av: str) -> str:
    return {"NETWORK": "NET", "ADJACENT": "ADJ", "LOCAL": "LOCAL", "PHYSICAL": "PHY"}.get(av.upper(), av[:5] or "N/A")

def _abbrev_pr(pr: str) -> str:
    return {"NONE": "NONE", "LOW": "LOW", "HIGH": "HIGH"}.get(pr.upper(), pr[:4] or "N/A")

def _tick(lst, color: str) -> str:
    return f"[{color}]✓[/{color}]" if lst else "[dim]✗[/dim]"

def _print_legend() -> None:
    console.print(
        "[dim]  EDB=Exploit-DB  PoC=GitHub PoC  Nuclei=Nuclei Template  "
        "MSF=Metasploit Module  KEV=CISA Known Exploited[/dim]"
    )


# ── Full CVE detail panel ──────────────────────────────────────────────────

def print_cve_detail(r: CVERecord) -> None:
    sev   = r.severity
    style = _SEV_STYLE.get(sev, "white")
    emoji = _SEV_EMOJI.get(sev, "")
    lines: List[str] = []

    lines.append(f"[dim]NVD Link:[/dim] [link={r.nvd_link}]{r.nvd_link}[/link]")
    lines.append(f"[dim]Published:[/dim] {(r.published or 'N/A')[:10]}  "
                 f"[dim]Modified:[/dim] {(r.last_modified or 'N/A')[:10]}")

    if r.description and r.description != "N/A":
        desc = r.description[:300] + ("…" if len(r.description) > 300 else "")
        lines.append(f"\n[dim]Description:[/dim] {desc}")

    if r.weaknesses:
        lines.append(f"[dim]Weaknesses:[/dim]  {', '.join(r.weaknesses)}")

    if r.cvss:
        lines.append(
            f"\n[bold]CVSS {r.cvss.version}:[/bold] [{style}]{r.cvss_score}[/{style}]  "
            f"[dim]AV:[/dim]{r.cvss.attack_vector or '?'}  "
            f"[dim]AC:[/dim]{r.cvss.attack_complexity or '?'}  "
            f"[dim]PR:[/dim]{r.cvss.privileges_required or '?'}  "
            f"[dim]UI:[/dim]{r.cvss.user_interaction or '?'}"
        )

    if r.epss_score is not None:
        pct = r.epss_percentile or 0
        lines.append(
            f"[bold]EPSS:[/bold] {r.epss_score:.4f} "
            f"({pct*100:.1f}th percentile — "
            f"{'⚠ High exploitation probability' if r.epss_score > 0.5 else 'moderate'})"
        )

    # KEV badge
    if r.in_kev:
        lines.append(
            f"\n[bold red]🔥 CISA KEV:[/bold red] Added {r.kev_date_added}  "
            f"Ransomware: {r.kev_ransomware_use or 'Unknown'}"
        )

    # Exploit-DB
    if r.exploits:
        lines.append(f"\n[bold magenta]Exploit-DB ({len(r.exploits)}):[/bold magenta]")
        for e in r.exploits[:5]:
            lines.append(
                f"  [magenta]▸ EDB-{e.id}[/magenta]  "
                f"[dim][{e.exploit_type or '?'}/{e.platform or '?'}][/dim]  "
                f"{e.description[:70]}  "
                f"[link={e.link}]{e.link}[/link]"
            )

    # GitHub PoCs
    if r.pocs:
        lines.append(f"\n[bold cyan]PoC References ({len(r.pocs)}):[/bold cyan]")
        for p in r.pocs[:8]:
            star_str = f"  ★{p.stars}" if p.stars else ""
            src_badge = f"[dim][{p.source}][/dim]"
            desc_str = f"  [dim]{p.description[:60]}[/dim]" if p.description else ""
            lines.append(f"  [cyan]▸[/cyan] [link={p.url}]{p.url}[/link]{star_str}  {src_badge}{desc_str}")

    # Nuclei templates
    if r.nuclei_templates:
        lines.append(f"\n[bold bright_magenta]Nuclei Templates ({len(r.nuclei_templates)}):[/bold bright_magenta]")
        for tmpl in r.nuclei_templates[:5]:
            sev_tag = f"[{_nuclei_sev_color(tmpl.severity)}]{tmpl.severity}[/{_nuclei_sev_color(tmpl.severity)}]"
            lines.append(
                f"  [bright_magenta]▸[/bright_magenta] {tmpl.template_id}  {sev_tag}  "
                f"[link={tmpl.url}]{tmpl.url}[/link]"
            )
        lines.append(
            f"  [dim]Run:[/dim] [bold]nuclei -t cves/ -id {r.cve_id.lower()}[/bold]"
        )

    # Metasploit
    if r.msf_modules:
        lines.append(f"\n[bold red]Metasploit Modules ({len(r.msf_modules)}):[/bold red]")
        for m in r.msf_modules[:3]:
            lines.append(
                f"  [red]▸[/red] [{m.module_type}] {m.fullname}"
                f"\n    [dim]{m.description[:100]}[/dim]"
            )
        lines.append(
            f"  [dim]Run:[/dim] [bold]msfconsole -q -x 'use {r.msf_modules[0].fullname}'[/bold]"
        )

    # Quick links
    links = [
        f"[link=https://nvd.nist.gov/vuln/detail/{r.cve_id}]NVD[/link]",
        f"[link=https://www.exploit-db.com/search?cve={r.cve_id.split('-')[-1]}]EDB[/link]",
        f"[link=https://sploitus.com/?query={r.cve_id}]Sploitus[/link]",
        f"[link=https://packetstormsecurity.com/search/?q={r.cve_id}&s=files]PacketStorm[/link]",
        f"[link=https://github.com/search?q={r.cve_id}&type=repositories]GitHub[/link]",
    ]
    lines.append(f"\n[dim]Quick Links:[/dim]  {'  ·  '.join(links)}")

    console.print(
        Panel(
            "\n".join(lines),
            title=f"[{style}]{emoji} {r.cve_id}  ─  {sev.value}[/{style}]",
            border_style=style or "white",
            expand=False,
        )
    )


def _nuclei_sev_color(sev: str) -> str:
    return {"critical": "bold red", "high": "red", "medium": "yellow",
            "low": "green", "info": "blue"}.get(sev.lower(), "white")


# ── Summary panel ──────────────────────────────────────────────────────────

def print_summary(result: ScanResult) -> None:
    lines = [
        f"[bold]Total CVEs:[/bold]       {result.total}",
        f"[bold red]Critical:[/bold red]         {result.critical_count}",
        f"[bold orange3]High:[/bold orange3]             {result.high_count}",
        f"[bold green]With Exploits:[/bold green]    {result.exploit_count}",
        f"[bold magenta]Nuclei Ready:[/bold magenta]     {result.nuclei_count}",
        f"[bold red]MSF Modules:[/bold red]      {result.msf_count}",
        f"[bold red]🔥 In CISA KEV:[/bold red]   {result.kev_count}",
    ]
    console.print(
        Panel("\n".join(lines), title="[bold]Scan Summary[/bold]",
              box=box.ROUNDED, border_style="cyan", expand=False)
    )


# ── Asset scan output ──────────────────────────────────────────────────────

def print_asset_result(result: AssetScanResult, show_detail: bool = False) -> None:
    """Print a full asset scan result including fingerprint and per-tech CVEs."""

    # Header panel
    status_style = "green" if (result.status_code or 0) < 400 else "red"
    header_lines = [
        f"[dim]URL:[/dim]        {result.final_url or result.url}",
        f"[dim]Status:[/dim]     [{status_style}]{result.status_code or 'N/A'}[/{status_style}]",
        f"[dim]Server:[/dim]     {result.server or 'N/A'}",
        f"[dim]CVEs Found:[/dim] {result.total_cves}  "
        f"[red]Critical: {result.critical_count}[/red]  "
        f"[bold red]Weaponised: {result.weaponised_count}[/bold red]",
    ]
    if result.error:
        header_lines.append(f"[red]Error:[/red] {result.error}")

    console.print(Panel("\n".join(header_lines),
                        title=f"[bold cyan]🌐 Asset: {result.url}[/bold cyan]",
                        border_style="cyan", expand=False))

    # Fingerprint table
    if result.technologies:
        tech_t = Table(title="Detected Technologies", box=box.SIMPLE, expand=False)
        tech_t.add_column("Technology", style="bold")
        tech_t.add_column("Version", style="yellow")
        tech_t.add_column("Categories")
        tech_t.add_column("Confidence", justify="right")
        for tech in result.technologies:
            conf_style = "green" if tech.confidence >= 80 else "yellow" if tech.confidence >= 50 else "dim"
            tech_t.add_row(
                tech.name,
                tech.version or "[dim]unknown[/dim]",
                ", ".join(tech.categories) or "—",
                f"[{conf_style}]{tech.confidence}%[/{conf_style}]",
            )
        console.print(tech_t)

    # Per-component CVE results
    for comp_result in result.cve_results:
        tech = comp_result.tech
        if not comp_result.records:
            console.print(f"  [dim]No CVEs found for {tech.name} {tech.version or ''}[/dim]")
            continue

        console.print(f"\n[bold]CVEs for [cyan]{tech.name}[/cyan] "
                      f"[yellow]{tech.version or ''}[/yellow][/bold]")
        print_cve_table(comp_result.records, show_description=show_detail)

    if result.cve_results:
        # Build a fake ScanResult for the summary
        from threattracer.core.scanner import ScanResult as SR
        flat = SR(cve_records=[r for cr in result.cve_results for r in cr.records])
        print_summary(flat)


def print_asset_batch(results: List[AssetScanResult]) -> None:
    """Summary table for a batch of asset scans."""
    t = Table(title="[bold]Asset Scan Summary[/bold]", box=box.ROUNDED, show_lines=True, expand=True)
    t.add_column("URL", style="cyan", no_wrap=False)
    t.add_column("Status", width=7, justify="center")
    t.add_column("Technologies", width=35)
    t.add_column("CVEs",  width=5, justify="right")
    t.add_column("Crit",  width=5, justify="right")
    t.add_column("KEV",   width=5, justify="right")
    t.add_column("MSF",   width=5, justify="right")
    t.add_column("Nuclei",width=7, justify="right")

    for r in results:
        status_style = "green" if (r.status_code or 0) < 400 else "red"
        techs_str = ", ".join(
            f"{t.name}{' '+t.version if t.version else ''}"
            for t in r.technologies[:4]
        ) or "[dim]none detected[/dim]"

        kev = sum(1 for cr in r.cve_results for rec in cr.records if rec.in_kev)
        msf = sum(1 for cr in r.cve_results for rec in cr.records if rec.msf_modules)
        nuc = sum(1 for cr in r.cve_results for rec in cr.records if rec.nuclei_templates)

        t.add_row(
            r.url,
            f"[{status_style}]{r.status_code or 'ERR'}[/{status_style}]",
            techs_str,
            str(r.total_cves),
            f"[red]{r.critical_count}[/red]" if r.critical_count else "0",
            f"[bold red]🔥{kev}[/bold red]" if kev else "0",
            f"[red]{msf}[/red]" if msf else "0",
            f"[magenta]{nuc}[/magenta]" if nuc else "0",
        )
    console.print(t)


# ── JSON output ────────────────────────────────────────────────────────────

def print_json(result: ScanResult) -> None:
    data = {
        "cpes": [m.model_dump() for m in result.cpes_found],
        "cves": [r.model_dump() for r in result.cve_records],
        "summary": {
            "total": result.total,
            "critical": result.critical_count,
            "high": result.high_count,
            "exploit_available": result.exploit_count,
            "in_kev": result.kev_count,
            "nuclei_templates": result.nuclei_count,
            "msf_modules": result.msf_count,
        },
    }
    console.print_json(json.dumps(data, default=str))


def print_asset_json(results: List[AssetScanResult]) -> None:
    console.print_json(json.dumps([r.model_dump() for r in results], default=str))


# ── CSV output ─────────────────────────────────────────────────────────────

def print_csv(result: ScanResult) -> None:
    out = io.StringIO()
    fields = [
        "cve_id", "severity", "cvss_score", "epss_score",
        "attack_vector", "privileges_required", "weaknesses",
        "in_kev", "kev_date_added", "kev_ransomware",
        "exploit_db_count", "poc_count", "nuclei_count", "msf_count",
        "exploit_db_links", "poc_links", "nuclei_links", "msf_modules",
        "published", "nvd_link", "description",
    ]
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for r in result.cve_records:
        writer.writerow({
            "cve_id":              r.cve_id,
            "severity":            r.severity.value,
            "cvss_score":          r.cvss_score or "",
            "epss_score":          r.epss_score or "",
            "attack_vector":       (r.cvss.attack_vector or "") if r.cvss else "",
            "privileges_required": (r.cvss.privileges_required or "") if r.cvss else "",
            "weaknesses":          "|".join(r.weaknesses),
            "in_kev":              "yes" if r.in_kev else "no",
            "kev_date_added":      r.kev_date_added or "",
            "kev_ransomware":      r.kev_ransomware_use or "",
            "exploit_db_count":    len(r.exploits),
            "poc_count":           len(r.pocs),
            "nuclei_count":        len(r.nuclei_templates),
            "msf_count":           len(r.msf_modules),
            "exploit_db_links":    "|".join(e.link for e in r.exploits),
            "poc_links":           "|".join(p.url for p in r.pocs),
            "nuclei_links":        "|".join(t.url for t in r.nuclei_templates),
            "msf_modules":         "|".join(m.fullname for m in r.msf_modules),
            "published":           (r.published or "")[:10],
            "nvd_link":            r.nvd_link,
            "description":         r.description[:200].replace("\n", " "),
        })
    sys.stdout.write(out.getvalue())
