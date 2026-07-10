"""
threattracer.cli
~~~~~~~~~~~~~~~~
All CLI commands live here.
"""

from __future__ import annotations

import asyncio
import logging
from enum import Enum
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console

from threattracer.cli.output import (
    err_console,
    make_progress,
    print_asset_batch,
    print_asset_json,
    print_asset_result,
    print_banner,
    print_cpe_table,
    print_csv,
    print_cve_detail,
    print_cve_table,
    print_json,
    print_llm_summary,
    print_summary,
    print_triage,
)
from threattracer.core.scanner import Scanner, ScanResult, sort_records
from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig, load_config, persist_api_key

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App-level help shown when user runs: threattracer --help
# ---------------------------------------------------------------------------

_APP_HELP = """
[bold cyan]ThreatTracer v5.0[/bold cyan] — CVE Intelligence, Triage & AI Briefing CLI

[dim]Original authors: @FR13ND0x7F  @0xCaretaker  @meppohak5[/dim]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[bold]COMMANDS[/bold]

  [bold cyan]scan[/bold cyan]       ·  CVE lookup by component name, CPE string, or CVE ID
  [bold cyan]asset[/bold cyan]      ·  Fingerprint a live URL and auto-scan all detected tech
  [bold cyan]doctor[/bold cyan]     ·  Check API keys, connectivity, cache, and local LLM
  [bold cyan]config[/bold cyan]     ·  Store NVD / GitHub keys & local-LLM settings permanently
  [bold cyan]sync[/bold cyan]       ·  Re-download the local Exploit-DB index
  [bold cyan]cache-cmd[/bold cyan]  ·  Clear or purge the local SQLite response cache

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[bold]QUICK EXAMPLES[/bold]

  [dim]# Scan a component and get a risk-ranked triage table[/dim]
  [green]threattracer scan -c apache -v 2.4.51 --summarize[/green]

  [dim]# Look up a CVE and write an HTML report with an AI briefing[/dim]
  [green]threattracer scan --cve CVE-2021-44228 -s --report log4shell.html[/green]

  [dim]# Fingerprint a live target, triage, and summarise[/dim]
  [green]threattracer asset https://target.com --summarize[/green]

  [dim]# Verify your environment (keys, network, local LLM)[/dim]
  [green]threattracer doctor[/green]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The [bold]--summarize[/bold] flag produces a prioritised triage table plus a plain-language
briefing. If a local LLM (Ollama or an OpenAI-compatible server) is reachable it
writes the briefing; otherwise a deterministic heuristic is used. No data leaves
your machine.

Run [bold]threattracer COMMAND --help[/bold] for full options and more examples.
"""

app = typer.Typer(
    name="threattracer",
    help=_APP_HELP,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()


class OutputMode(str, Enum):
    table  = "table"
    json   = "json"
    csv    = "csv"
    silent = "silent"


class SortField(str, Enum):
    cvss      = "cvss"
    epss      = "epss"
    published = "published"
    kev       = "kev"


class LLMProvider(str, Enum):
    auto   = "auto"
    ollama = "ollama"
    openai = "openai"
    off    = "off"


# =============================================================================
#  scan
# =============================================================================

@app.command()
def scan(
    component:    Optional[str] = typer.Option(None, "-c", "--component",
                                               help="Component / product name  (requires -v)"),
    version:      Optional[str] = typer.Option(None, "-v", "--version",
                                               help="Component version string"),
    cpe:          Optional[str] = typer.Option(None, "--cpe",
                                               help="Full CPE 2.3 string"),
    cve:          Optional[str] = typer.Option(None, "--cve",
                                               help="CVE ID  e.g. CVE-2021-44228"),

    nvd_key:      Optional[str] = typer.Option(None, "--api",
                                               help="NVD API key (higher rate limit)"),
    github_token: Optional[str] = typer.Option(None, "--github-token",
                                               help="GitHub token — enables PoC + Nuclei search"),
    noapi:        bool          = typer.Option(False, "--noapi",
                                               help="Force unauthenticated NVD mode"),

    no_exploits:  bool = typer.Option(False, "--no-exploits", help="Skip Exploit-DB lookup"),
    no_pocs:      bool = typer.Option(False, "--no-pocs",     help="Skip GitHub PoC search"),
    no_epss:      bool = typer.Option(False, "--no-epss",     help="Skip EPSS score fetch"),
    no_kev:       bool = typer.Option(False, "--no-kev",      help="Skip CISA KEV catalog check"),
    no_nuclei:    bool = typer.Option(False, "--no-nuclei",   help="Skip Nuclei template lookup"),
    no_msf:       bool = typer.Option(False, "--no-msf",      help="Skip Metasploit module check"),

    summarize:    bool          = typer.Option(False, "-s", "--summarize",
                                               help="Show a risk-ranked triage table + a plain-language briefing"),
    report:       Optional[Path] = typer.Option(None, "--report",
                                               help="Write a full report to FILE (.md or .html)"),
    llm_provider: Optional[LLMProvider] = typer.Option(None, "--llm-provider",
                                               help="LLM backend for the briefing: auto | ollama | openai | off"),
    llm_model:    Optional[str] = typer.Option(None, "--llm-model",
                                               help="Local model name (e.g. llama3.2, qwen2.5)"),
    top:          int           = typer.Option(10, "--top",
                                               help="How many findings in the triage table  (default 10)"),

    output:    OutputMode   = typer.Option(OutputMode.table, "-o", "--output",
                                           help="Output format: table | json | csv | silent"),
    detail:    bool         = typer.Option(False, "-d", "--detail",
                                           help="Show full detail panel for every CVE"),
    severity:  Optional[str] = typer.Option(None, "--severity",
                                            help="Comma-separated filter  e.g. critical,high"),
    since:     Optional[int] = typer.Option(None, "--since",
                                            help="Only CVEs published in YYYY or later"),
    limit:     int           = typer.Option(50, "--limit",
                                            help="Max CVEs to display  (default 50)"),
    sort:      SortField     = typer.Option(SortField.cvss, "--sort",
                                            help="Sort order: cvss | epss | published | kev"),
    top_cpes:  int           = typer.Option(5, "--top-cpes",
                                            help="Max CPEs to query when using -c/-v"),
    verbose:   bool = typer.Option(False, "--verbose", help="INFO-level logging"),
    debug_log: bool = typer.Option(False, "--debug",   help="DEBUG-level logging"),
) -> None:
    """
    [bold]Scan[/bold] for CVEs by component name, CPE string, or CVE ID.

    \b
    ── BY COMPONENT NAME ────────────────────────────────────────────────────
      threattracer scan -c apache -v 2.4.51
      threattracer scan -c log4j -v 2.14.1 --summarize
      threattracer scan -c wordpress -v 6.4.1 --severity critical,high

    ── BY CVE ID ────────────────────────────────────────────────────────────
      threattracer scan --cve CVE-2021-44228 --detail
      threattracer scan --cve CVE-2021-44228 -s --report log4shell.html

    ── BY CPE STRING ────────────────────────────────────────────────────────
      threattracer scan --cpe "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

    ── TRIAGE & AI BRIEFING ─────────────────────────────────────────────────
      threattracer scan -c struts -v 2.5.10 --summarize --top 15
      threattracer scan -c openssl -v 3.0.7 -s --llm-provider ollama --llm-model qwen2.5
      threattracer scan -c nginx -v 1.18 -s --report nginx.md
    """

    _configure_logging(verbose, debug_log)

    if output not in (OutputMode.json, OutputMode.csv):
        print_banner()

    if component and not version:
        err_console.print("[red]Error:[/red] --component requires --version (-v)")
        raise typer.Exit(1)
    if not any([component, cpe, cve]):
        err_console.print("[red]Error:[/red] Supply one of: --component, --cpe, --cve")
        raise typer.Exit(1)

    cfg = load_config(nvd_api_key=None if noapi else nvd_key, github_token=github_token)

    try:
        result: ScanResult = asyncio.run(
            _run_scan(
                config=cfg,
                component=component, version=version,
                cpe_string=cpe,
                cve_id=cve.upper() if cve else None,
                include_exploits=not no_exploits,
                include_pocs=not no_pocs,
                enrich_epss=not no_epss,
                include_kev=not no_kev,
                include_nuclei=not no_nuclei,
                include_msf=not no_msf,
                top_cpes=top_cpes,
            )
        )
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(130)
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Scan failed:[/red] {type(exc).__name__}: {exc}")
        log.debug("scan exception", exc_info=True)
        raise typer.Exit(1)

    records = result.cve_records
    if severity:
        allowed = {s.strip().upper() for s in severity.split(",")}
        records = [r for r in records if r.severity.value in allowed]
    if since:
        records = [r for r in records if (r.published or "") >= str(since)]

    records = sort_records(records, sort.value)[:limit]
    result.cve_records = records

    target_label = _scan_target_label(component, version, cpe, cve)

    if output == OutputMode.silent:
        pass
    elif output == OutputMode.json:
        print_json(result)
    elif output == OutputMode.csv:
        print_csv(result)
    else:
        if result.cpes_found:
            print_cpe_table(result.cpes_found)
        if records:
            print_cve_table(records, show_description=detail)
        else:
            console.print("[yellow]No CVEs found matching the given filters.[/yellow]")
        print_summary(result)

    # ── Triage + AI briefing + report ─────────────────────────────────
    if summarize or report:
        _render_briefing(
            cfg=cfg,
            records=records,
            target=target_label,
            scan_type="cve" if cve else "cpe" if cpe else "component",
            summarize=summarize,
            report=report,
            llm_provider=llm_provider.value if llm_provider else None,
            llm_model=llm_model,
            top=top,
            quiet=output in (OutputMode.json, OutputMode.csv, OutputMode.silent),
        )


# =============================================================================
#  asset
# =============================================================================

@app.command()
def asset(
    url:          Optional[str]  = typer.Argument(None,
                                                  help="Target URL  e.g. https://example.com"),
    file:         Optional[Path] = typer.Option(None, "--file", "-f",
                                                help="File with one URL per line — enables batch mode"),
    concurrency:  int            = typer.Option(3, "--concurrency", "-j",
                                                help="Parallel scans in batch mode  (default 3)"),

    nvd_key:      Optional[str]  = typer.Option(None, "--api",          help="NVD API key"),
    github_token: Optional[str]  = typer.Option(None, "--github-token", help="GitHub token"),

    no_exploits:  bool = typer.Option(False, "--no-exploits", help="Skip Exploit-DB"),
    no_pocs:      bool = typer.Option(False, "--no-pocs",     help="Skip GitHub PoC search"),
    no_epss:      bool = typer.Option(False, "--no-epss",     help="Skip EPSS score fetch"),
    no_kev:       bool = typer.Option(False, "--no-kev",      help="Skip CISA KEV catalog"),
    no_nuclei:    bool = typer.Option(False, "--no-nuclei",   help="Skip Nuclei template lookup"),
    no_msf:       bool = typer.Option(False, "--no-msf",      help="Skip Metasploit module check"),

    summarize:    bool          = typer.Option(False, "-s", "--summarize",
                                               help="Show a risk-ranked triage table + a plain-language briefing"),
    report:       Optional[Path] = typer.Option(None, "--report",
                                               help="Write a full report to FILE (.md or .html)"),
    llm_provider: Optional[LLMProvider] = typer.Option(None, "--llm-provider",
                                               help="LLM backend: auto | ollama | openai | off"),
    llm_model:    Optional[str] = typer.Option(None, "--llm-model", help="Local model name"),
    top:          int           = typer.Option(10, "--top", help="Findings in the triage table"),

    severity:     Optional[str] = typer.Option(None, "--severity",
                                               help="Filter  e.g. critical,high"),
    since:        Optional[int] = typer.Option(None, "--since",
                                               help="Only CVEs >= YYYY"),
    limit:        int           = typer.Option(20, "--limit",
                                               help="Max CVEs shown per technology  (default 20)"),
    sort:         SortField     = typer.Option(SortField.cvss, "--sort",
                                               help="Sort order: cvss | epss | published | kev"),
    output:       OutputMode    = typer.Option(OutputMode.table, "-o", "--output",
                                               help="Output format: table | json | silent"),
    detail:       bool          = typer.Option(False, "-d", "--detail",
                                               help="Show full CVE detail panels per technology"),
    min_conf:     int           = typer.Option(50, "--min-confidence",
                                               help="Min tech detection confidence 0-100  (default 50)"),
    verbose:      bool = typer.Option(False, "--verbose", help="INFO-level logging"),
    debug_log:    bool = typer.Option(False, "--debug",   help="DEBUG-level logging"),
) -> None:
    """
    [bold]Asset scan[/bold]: fingerprint a live URL, detect the tech stack, then auto-lookup CVEs.

    \b
    ── SINGLE TARGET ────────────────────────────────────────────────────────
      threattracer asset https://example.com
      threattracer asset https://target.com --summarize
      threattracer asset https://target.com -s --report target.html

    ── BATCH MODE (file with one URL per line) ───────────────────────────────
      threattracer asset --file targets.txt --concurrency 5 --summarize
      threattracer asset --file scope.txt --severity critical,high -o json

    ── BUG BOUNTY WORKFLOW ──────────────────────────────────────────────────
      subfinder -d example.com -silent | sed 's|^|https://|' > subs.txt
      threattracer asset --file subs.txt -j 10 --severity critical,high -s
    """

    _configure_logging(verbose, debug_log)

    if not url and not file:
        err_console.print("[red]Error:[/red] Provide a URL argument or --file targets.txt")
        raise typer.Exit(1)

    if output not in (OutputMode.json, OutputMode.csv):
        print_banner()

    cfg = load_config(nvd_api_key=nvd_key, github_token=github_token)

    urls: List[str] = []
    if url:
        urls.append(_normalise_url(url))
    if file:
        if not file.exists():
            err_console.print(f"[red]Error:[/red] File not found: {file}")
            raise typer.Exit(1)
        try:
            lines = file.read_text().splitlines()
        except OSError as exc:
            err_console.print(f"[red]Error:[/red] Could not read {file}: {exc}")
            raise typer.Exit(1)
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(_normalise_url(line))

    if not urls:
        err_console.print("[red]Error:[/red] No valid URLs found")
        raise typer.Exit(1)

    scan_kwargs = dict(
        include_exploits=not no_exploits,
        include_pocs=not no_pocs,
        enrich_epss=not no_epss,
        include_kev=not no_kev,
        include_nuclei=not no_nuclei,
        include_msf=not no_msf,
        min_confidence=min_conf,
    )

    try:
        results = asyncio.run(_run_asset_scan(cfg, urls, concurrency, scan_kwargs))
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(130)
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Asset scan failed:[/red] {type(exc).__name__}: {exc}")
        log.debug("asset scan exception", exc_info=True)
        raise typer.Exit(1)

    for ar in results:
        for cr in ar.cve_results:
            recs = cr.records
            if severity:
                allowed = {s.strip().upper() for s in severity.split(",")}
                recs = [r for r in recs if r.severity.value in allowed]
            if since:
                recs = [r for r in recs if (r.published or "") >= str(since)]
            cr.records = sort_records(recs, sort.value)[:limit]

    quiet = output in (OutputMode.json, OutputMode.csv, OutputMode.silent)

    if output == OutputMode.json:
        print_asset_json(results)
    elif output == OutputMode.silent:
        pass
    elif len(results) > 1:
        print_asset_batch(results)
        if detail:
            for ar in results:
                print_asset_result(ar, show_detail=True)
    else:
        print_asset_result(results[0], show_detail=detail)

    # ── Triage + AI briefing + report (combined across all targets) ───
    if summarize or report:
        from threattracer.core.triage import summarise_asset, summarise_records

        flat_records = [r for ar in results for cr in ar.cve_results for r in cr.records]
        component_map: dict = {}
        for ar in results:
            for cr in ar.cve_results:
                label = f"{cr.tech.name} {cr.tech.version or ''}".strip()
                for rec in cr.records:
                    component_map.setdefault(rec.cve_id, label)

        target = results[0].final_url or results[0].url if len(results) == 1 \
            else f"{len(results)} targets"

        _render_briefing(
            cfg=cfg,
            records=flat_records,
            target=target,
            scan_type="asset",
            summarize=summarize,
            report=report,
            llm_provider=llm_provider.value if llm_provider else None,
            llm_model=llm_model,
            top=top,
            quiet=quiet,
            component_map=component_map,
        )


# =============================================================================
#  doctor
# =============================================================================

@app.command()
def doctor(
    verbose: bool = typer.Option(False, "--verbose", help="INFO-level logging"),
) -> None:
    """
    [bold]Doctor[/bold]: check API keys, network connectivity, cache, and local LLM readiness.

    \b
    Run this first if a scan is slow or empty — it tells you what is and isn't
    reachable without running a full scan.
    """
    _configure_logging(verbose, False)
    print_banner()
    cfg = load_config()

    from rich.table import Table
    from rich import box

    def _mask(secret: Optional[str]) -> str:
        if not secret:
            return "[dim]not set[/dim]"
        return f"[green]set[/green] [dim](…{secret[-4:]})[/dim]" if len(secret) >= 4 else "[green]set[/green]"

    t = Table(title="[bold]Environment[/bold]", box=box.ROUNDED, show_lines=False)
    t.add_column("Check", style="cyan")
    t.add_column("Status")
    t.add_row("NVD API key", _mask(cfg.nvd_api_key))
    t.add_row("GitHub token", _mask(cfg.github_token))
    t.add_row("Cache DB", str(cfg.cache_db_path))
    t.add_row("LLM provider", cfg.llm_provider)
    t.add_row("LLM model", cfg.llm_model)
    console.print(t)

    results = asyncio.run(_run_doctor(cfg))

    n = Table(title="[bold]Connectivity[/bold]", box=box.ROUNDED)
    n.add_column("Service", style="cyan")
    n.add_column("Reachable")
    n.add_column("Detail", style="dim")
    for name, ok, detail in results["network"]:
        badge = "[green]✓[/green]" if ok else "[red]✗[/red]"
        n.add_row(name, badge, detail)
    console.print(n)

    llm = results["llm"]
    l = Table(title="[bold]Local LLM[/bold]", box=box.ROUNDED)
    l.add_column("Backend", style="cyan")
    l.add_column("Reachable")
    l.add_column("Endpoint", style="dim")
    l.add_row("Ollama", "[green]✓[/green]" if llm["ollama"] else "[red]✗[/red]", cfg.llm_ollama_url)
    l.add_row("OpenAI-compatible", "[green]✓[/green]" if llm["openai"] else "[red]✗[/red]", cfg.llm_openai_url)
    console.print(l)

    if not (llm["ollama"] or llm["openai"]):
        console.print(
            "[dim]No local LLM detected. --summarize will use the built-in heuristic. "
            "To enable AI briefings, run Ollama ([bold]ollama serve[/bold] + "
            f"[bold]ollama pull {cfg.llm_model}[/bold]) or any OpenAI-compatible local server.[/dim]"
        )
    else:
        console.print("[green]Local LLM detected — --summarize will produce AI briefings.[/green]")


# =============================================================================
#  config
# =============================================================================

@app.command(name="config")
def config_cmd(
    nvd_key:       Optional[str] = typer.Option(None, "--nvd-key",
                                                help="NVD API key to store permanently"),
    github_token:  Optional[str] = typer.Option(None, "--github-token",
                                                help="GitHub personal access token to store"),
    llm_provider:  Optional[LLMProvider] = typer.Option(None, "--llm-provider",
                                                help="Default LLM backend: auto | ollama | openai | off"),
    llm_model:     Optional[str] = typer.Option(None, "--llm-model",
                                                help="Default local model name"),
    llm_ollama_url: Optional[str] = typer.Option(None, "--llm-ollama-url",
                                                help="Ollama base URL (default http://localhost:11434)"),
    llm_openai_url: Optional[str] = typer.Option(None, "--llm-openai-url",
                                                help="OpenAI-compatible base URL (default http://localhost:8080)"),
    show:          bool = typer.Option(False, "--show", help="Show the current stored config"),
) -> None:
    """
    [bold]Store[/bold] keys & LLM settings in [cyan]~/.threattracer/config.json[/cyan].

    \b
    ── EXAMPLES ─────────────────────────────────────────────────────────────
      threattracer config --nvd-key YOUR_NVD_KEY --github-token YOUR_GH_TOKEN
      threattracer config --llm-provider ollama --llm-model llama3.2
      threattracer config --llm-provider openai --llm-openai-url http://localhost:1234
      threattracer config --show

    ── ENV VARS (alternative) ───────────────────────────────────────────────
      export NVD_API_KEY=...   GITHUB_TOKEN=...
      export THREATTRACER_LLM_PROVIDER=ollama  THREATTRACER_LLM_MODEL=llama3.2
    """
    stored_any = False
    if nvd_key:
        persist_api_key(nvd_key, "nvd");            console.print("[green]✓ NVD API key stored.[/green]"); stored_any = True
    if github_token:
        persist_api_key(github_token, "github");    console.print("[green]✓ GitHub token stored.[/green]"); stored_any = True
    if llm_provider:
        persist_api_key(llm_provider.value, "llm_provider"); console.print(f"[green]✓ LLM provider = {llm_provider.value}[/green]"); stored_any = True
    if llm_model:
        persist_api_key(llm_model, "llm_model");     console.print(f"[green]✓ LLM model = {llm_model}[/green]"); stored_any = True
    if llm_ollama_url:
        persist_api_key(llm_ollama_url, "llm_ollama_url"); console.print("[green]✓ Ollama URL stored.[/green]"); stored_any = True
    if llm_openai_url:
        persist_api_key(llm_openai_url, "llm_openai_url"); console.print("[green]✓ OpenAI URL stored.[/green]"); stored_any = True

    if show or not stored_any:
        cfg = load_config()
        console.print("\n[bold]Current effective config[/bold]")
        console.print(f"  NVD key      : {'set' if cfg.nvd_api_key else 'not set'}")
        console.print(f"  GitHub token : {'set' if cfg.github_token else 'not set'}")
        console.print(f"  LLM provider : {cfg.llm_provider}")
        console.print(f"  LLM model    : {cfg.llm_model}")
        console.print(f"  Ollama URL   : {cfg.llm_ollama_url}")
        console.print(f"  OpenAI URL   : {cfg.llm_openai_url}")
        if not stored_any and not show:
            console.print("\n[dim]Nothing stored. Pass --nvd-key / --github-token / --llm-provider etc.[/dim]")
            console.print("  NVD key : [link=https://nvd.nist.gov/developers/request-an-api-key]https://nvd.nist.gov/developers/request-an-api-key[/link]")
            console.print("  GitHub  : [link=https://github.com/settings/tokens]https://github.com/settings/tokens[/link]")


# =============================================================================
#  sync
# =============================================================================

@app.command()
def sync() -> None:
    """
    [bold]Sync[/bold] the local Exploit-DB CSV index from GitLab.

    \b
      threattracer sync
    """
    from threattracer.core.exploitdb import ExploitDBClient
    from threattracer.utils.http_client import AsyncHTTPClient

    cfg = load_config()

    async def _sync() -> int:
        async with AsyncHTTPClient(cfg) as http:
            async with ResponseCache(cfg) as cache:
                return await ExploitDBClient(cfg, http, cache).sync()

    console.print("[cyan]Syncing Exploit-DB index...[/cyan]")
    try:
        n = asyncio.run(_sync())
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Sync failed:[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(1)
    console.print(f"[green]✓ Exploit-DB synced: {n:,} entries.[/green]")


# =============================================================================
#  cache-cmd
# =============================================================================

@app.command(name="cache-cmd")
def cache_cmd(
    clear: bool = typer.Option(False, "--clear",         help="Delete ALL cached entries"),
    purge: bool = typer.Option(False, "--purge-expired", help="Delete only expired entries"),
) -> None:
    """
    [bold]Manage[/bold] the local SQLite response cache at [cyan]~/.threattracer/cache.db[/cyan].

    \b
      threattracer cache-cmd --purge-expired
      threattracer cache-cmd --clear
    """
    cfg = load_config()

    async def _manage() -> None:
        async with ResponseCache(cfg) as c:
            if clear:
                await c.clear_all()
                console.print("[green]✓ Cache cleared.[/green]")
            elif purge:
                n = await c.purge_expired()
                console.print(f"[green]✓ Purged {n} expired entries.[/green]")
            else:
                console.print("[yellow]Specify --clear or --purge-expired.[/yellow]")

    try:
        asyncio.run(_manage())
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Cache op failed:[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(1)


# =============================================================================
#  Internal helpers
# =============================================================================

def _render_briefing(
    cfg: AppConfig,
    records: list,
    target: str,
    scan_type: str,
    summarize: bool,
    report: Optional[Path],
    llm_provider: Optional[str],
    llm_model: Optional[str],
    top: int,
    quiet: bool,
    component_map: Optional[dict] = None,
) -> None:
    """Build triage + optional AI briefing, print them, and/or write a report."""
    from threattracer.core.llm_summary import LLMSummariser
    from threattracer.core.triage import summarise_records

    summary = summarise_records(
        records, target=target, scan_type=scan_type,
        top_n=max(top, 10), component_map=component_map,
    )

    # If the user only asked for a report (no --summarize), keep it offline
    # (heuristic) unless they explicitly chose an LLM provider.
    if summarize:
        eff_provider = llm_provider or cfg.llm_provider
    else:
        eff_provider = llm_provider or "off"

    llm_cfg = cfg.with_overrides(llm_provider=eff_provider, llm_model=llm_model)

    try:
        llm_result = asyncio.run(LLMSummariser(llm_cfg).summarise(summary))
    except Exception as exc:  # noqa: BLE001 — briefing must never crash the run
        from threattracer.core.llm_summary import heuristic_summary
        from threattracer.utils.models import LLMSummary
        log.debug("briefing failed: %s", exc, exc_info=True)
        llm_result = LLMSummary(
            text=heuristic_summary(summary), engine="heuristic",
            degraded=True, note=f"{type(exc).__name__}: {exc}",
        )

    if summarize and not quiet:
        print_triage(summary, top_n=top)
        print_llm_summary(llm_result)

    if report:
        from threattracer.cli.report import write_report
        try:
            written = write_report(report, summary, records, llm_result)
            (err_console if quiet else console).print(
                f"[green]✓ Report written:[/green] {written}"
            )
        except OSError as exc:
            err_console.print(f"[red]Could not write report to {report}:[/red] {exc}")


def _scan_target_label(
    component: Optional[str], version: Optional[str],
    cpe: Optional[str], cve: Optional[str],
) -> str:
    if cve:
        return cve.upper()
    if cpe:
        return cpe
    if component:
        return f"{component} {version or ''}".strip()
    return "scan"


async def _run_scan(
    config: AppConfig,
    component: Optional[str],
    version:   Optional[str],
    cpe_string: Optional[str],
    cve_id:    Optional[str],
    include_exploits: bool,
    include_pocs:     bool,
    enrich_epss:      bool,
    include_kev:      bool,
    include_nuclei:   bool,
    include_msf:      bool,
    top_cpes:         int,
) -> ScanResult:
    async with Scanner(config) as scanner:
        with make_progress() as progress:
            if cve_id:
                progress.add_task(f"Fetching {cve_id}...", total=None)
                return await scanner.scan_cve(
                    cve_id, include_exploits, include_pocs, enrich_epss,
                    include_kev, include_nuclei, include_msf,
                )
            elif cpe_string:
                progress.add_task("Fetching CVEs for CPE...", total=None)
                return await scanner.scan_cpe(
                    cpe_string, include_exploits, include_pocs, enrich_epss,
                    include_kev, include_nuclei, include_msf,
                )
            else:
                progress.add_task(f"Scanning {component} {version}...", total=None)
                return await scanner.scan_component(
                    component,   # type: ignore
                    version,     # type: ignore
                    include_exploits, include_pocs, enrich_epss,
                    include_kev, include_nuclei, include_msf,
                    top_cpes,
                )


async def _run_asset_scan(
    config: AppConfig,
    urls: List[str],
    concurrency: int,
    scan_kwargs: dict,
):
    from threattracer.core.asset_scanner import AssetScanner
    from threattracer.utils.http_client import AsyncHTTPClient

    async with AsyncHTTPClient(config) as http:
        async with ResponseCache(config) as cache:
            scanner = AssetScanner(config, http, cache)
            with make_progress() as progress:
                task = progress.add_task(
                    f"Scanning {len(urls)} target(s)...", total=len(urls)
                )
                sem = asyncio.Semaphore(max(1, concurrency))

                async def _one(u: str):
                    async with sem:
                        r = await scanner.scan_url(u, **scan_kwargs)
                        progress.advance(task)
                        return r

                return await asyncio.gather(*[_one(u) for u in urls])


async def _run_doctor(config: AppConfig) -> dict:
    """Probe network services and local LLM backends. Never raises."""
    import httpx
    from threattracer.core.llm_summary import LLMSummariser

    network = []
    probes = [
        ("NVD API", config.nvd_cve_endpoint, {"cveId": "CVE-2021-44228"}),
        ("EPSS", config.epss_base_url, {"cve": "CVE-2021-44228"}),
        ("CISA KEV", config.kev_url, None),
        ("GitHub API", "https://api.github.com/rate_limit", None),
    ]
    async with httpx.AsyncClient(timeout=8, follow_redirects=True,
                                 headers={"User-Agent": config.user_agent}) as client:
        for name, url, params in probes:
            try:
                r = await client.get(url, params=params)
                ok = r.status_code < 500
                network.append((name, ok, f"HTTP {r.status_code}"))
            except Exception as exc:  # noqa: BLE001
                network.append((name, False, f"{type(exc).__name__}"))

    llm = await LLMSummariser(config).probe()
    return {"network": network, "llm": llm}


def _normalise_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _configure_logging(verbose: bool, debug: bool) -> None:
    level = logging.WARNING
    if verbose:
        level = logging.INFO
    if debug:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )
