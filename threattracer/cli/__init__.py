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
    print_summary,
)
from threattracer.core.scanner import Scanner, ScanResult, sort_records
from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig, load_config, persist_api_key

# ---------------------------------------------------------------------------
# App-level help shown when user runs: threattracer --help
# ---------------------------------------------------------------------------

_APP_HELP = """
[bold cyan]ThreatTracer v4.1[/bold cyan] — CVE Intelligence & Exploit-Hunting CLI

[dim]Original authors: @FR13ND0x7F  @0xCaretaker  @meppohak5[/dim]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[bold]COMMANDS[/bold]

  [bold cyan]scan[/bold cyan]       ·  CVE lookup by component name, CPE string, or CVE ID
  [bold cyan]asset[/bold cyan]      ·  Fingerprint a live URL and auto-scan all detected tech
  [bold cyan]config[/bold cyan]     ·  Store NVD / GitHub API keys permanently
  [bold cyan]sync[/bold cyan]       ·  Re-download the local Exploit-DB index
  [bold cyan]cache-cmd[/bold cyan]  ·  Clear or purge the local SQLite response cache

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[bold]QUICK EXAMPLES[/bold]

  [dim]# Scan by component name + version[/dim]
  [green]threattracer scan -c apache -v 2.4.51[/green]

  [dim]# Look up a specific CVE with full detail[/dim]
  [green]threattracer scan --cve CVE-2021-44228 --detail[/green]

  [dim]# Scan by CPE string, output JSON[/dim]
  [green]threattracer scan --cpe "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" -o json[/green]

  [dim]# Fingerprint a live target and find all CVEs[/dim]
  [green]threattracer asset https://target.com[/green]

  [dim]# Batch scan multiple targets from a file[/dim]
  [green]threattracer asset --file targets.txt --concurrency 5[/green]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
      threattracer scan -c nginx -v 1.18.0
      threattracer scan -c "peel shopping" -v 9.4.0
      threattracer scan -c log4j -v 2.14.1 --detail
      threattracer scan -c wordpress -v 6.4.1 --severity critical,high

    ── BY CVE ID ────────────────────────────────────────────────────────────
      threattracer scan --cve CVE-2021-44228
      threattracer scan --cve CVE-2021-44228 --detail
      threattracer scan --cve CVE-2023-44487 -o json
      threattracer scan --cve CVE-2017-5638 --no-epss --no-msf

    ── BY CPE STRING ────────────────────────────────────────────────────────
      threattracer scan --cpe "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
      threattracer scan --cpe "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*" -o json

    ── FILTERING & OUTPUT ───────────────────────────────────────────────────
      threattracer scan -c openssl -v 3.0.7 --severity critical
      threattracer scan -c struts -v 2.5.10 --since 2020 --sort epss
      threattracer scan -c apache -v 2.4 --sort kev --limit 10
      threattracer scan -c nginx -v 1.18 -o csv > nginx-cves.csv
      threattracer scan -c apache -v 2.4 -o json | jq '.summary'

    ── WITH API KEYS ────────────────────────────────────────────────────────
      threattracer scan -c apache -v 2.4 --api $NVD_KEY --github-token $GH_TOKEN
      threattracer config --nvd-key $NVD_KEY --github-token $GH_TOKEN
      threattracer scan -c apache -v 2.4                  # keys auto-loaded
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

    records = result.cve_records
    if severity:
        allowed = {s.strip().upper() for s in severity.split(",")}
        records = [r for r in records if r.severity.value in allowed]
    if since:
        records = [r for r in records if (r.published or "") >= str(since)]

    records = sort_records(records, sort.value)[:limit]
    result.cve_records = records

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
    Detects technologies via Wappalyzer + HTTP header + body fingerprinting,
    then runs the full CVE / Exploit-DB / PoC / KEV / Nuclei / MSF pipeline
    automatically for every component where a version is found.

    ── SINGLE TARGET ────────────────────────────────────────────────────────
      threattracer asset https://example.com
      threattracer asset http://10.10.10.5
      threattracer asset https://target.com --detail
      threattracer asset https://target.com --severity critical --sort kev
      threattracer asset https://target.com -o json

    ── BATCH MODE (file with one URL per line) ───────────────────────────────
      threattracer asset --file targets.txt
      threattracer asset --file targets.txt --concurrency 5
      threattracer asset --file targets.txt --severity critical -o json
      threattracer asset --file scope.txt --since 2022 --sort epss

    ── BUG BOUNTY WORKFLOW ──────────────────────────────────────────────────
      [dim]# Find only weaponised / KEV CVEs on a target[/dim]
      threattracer asset https://target.com --severity critical --sort kev -d

      [dim]# Pipe JSON into jq for automation[/dim]
      threattracer asset https://target.com -o json | jq '.[].cve_results'

      [dim]# Scan all subdomains from Subfinder output[/dim]
      subfinder -d example.com -silent | sed 's|^|https://|' > subs.txt
      threattracer asset --file subs.txt --concurrency 10 --severity critical,high

    ── TARGETS.TXT FORMAT ───────────────────────────────────────────────────
      [dim]# Lines starting with # are ignored[/dim]
      https://example.com
      https://api.example.com
      http://10.10.10.5:8080
      https://staging.example.com
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
        for line in file.read_text().splitlines():
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

    results = asyncio.run(_run_asset_scan(cfg, urls, concurrency, scan_kwargs))

    for ar in results:
        for cr in ar.cve_results:
            recs = cr.records
            if severity:
                allowed = {s.strip().upper() for s in severity.split(",")}
                recs = [r for r in recs if r.severity.value in allowed]
            if since:
                recs = [r for r in recs if (r.published or "") >= str(since)]
            cr.records = sort_records(recs, sort.value)[:limit]

    if output == OutputMode.json:
        print_asset_json(results)
        return
    if output == OutputMode.silent:
        return

    if len(results) > 1:
        print_asset_batch(results)
        if detail:
            for ar in results:
                print_asset_result(ar, show_detail=True)
    else:
        print_asset_result(results[0], show_detail=detail)


# =============================================================================
#  config
# =============================================================================

@app.command(name="config")
def config_cmd(
    nvd_key:      Optional[str] = typer.Option(None, "--nvd-key",
                                               help="NVD API key to store permanently"),
    github_token: Optional[str] = typer.Option(None, "--github-token",
                                               help="GitHub personal access token to store permanently"),
) -> None:
    """
    [bold]Store[/bold] API keys in [cyan]~/.threattracer/config.json[/cyan].

    \b
    Keys are loaded automatically on every scan — no need to pass them each time.

    ── EXAMPLES ─────────────────────────────────────────────────────────────
      threattracer config --nvd-key YOUR_NVD_KEY
      threattracer config --github-token YOUR_GITHUB_TOKEN
      threattracer config --nvd-key YOUR_NVD_KEY --github-token YOUR_GITHUB_TOKEN

    ── ENV VARS (alternative to storing) ────────────────────────────────────
      export NVD_API_KEY=your_key
      export GITHUB_TOKEN=your_token

    ── GET YOUR KEYS ────────────────────────────────────────────────────────
      NVD API key :  https://nvd.nist.gov/developers/request-an-api-key
      GitHub token:  https://github.com/settings/tokens  (public_repo scope)
    """
    if nvd_key:
        persist_api_key(nvd_key, "nvd")
        console.print("[green]✓ NVD API key stored.[/green]")
    if github_token:
        persist_api_key(github_token, "github")
        console.print("[green]✓ GitHub token stored.[/green]")
    if not nvd_key and not github_token:
        console.print("[yellow]No key provided. Use --nvd-key or --github-token.[/yellow]")
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
    The index is cached locally at ~/.threattracer/exploitdb.csv and in
    the SQLite cache. It is re-downloaded automatically when the 6-hour TTL
    expires. Use this command to force an immediate refresh.

    ── EXAMPLES ─────────────────────────────────────────────────────────────
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
    n = asyncio.run(_sync())
    console.print(f"[green]✓ Exploit-DB synced: {n:,} entries.[/green]")


# =============================================================================
#  cache-cmd
# =============================================================================

@app.command(name="cache-cmd")
def cache_cmd(
    clear: bool = typer.Option(False, "--clear",
                               help="Delete ALL cached entries"),
    purge: bool = typer.Option(False, "--purge-expired",
                               help="Delete only entries whose TTL has expired"),
) -> None:
    """
    [bold]Manage[/bold] the local SQLite response cache at [cyan]~/.threattracer/cache.db[/cyan].

    \b
    All API responses (NVD, EPSS, GitHub, KEV, Nuclei, ExploitDB) are cached
    for 6 hours by default. Use these commands to force fresh data.

    ── EXAMPLES ─────────────────────────────────────────────────────────────
      threattracer cache-cmd --purge-expired   # remove stale entries only
      threattracer cache-cmd --clear           # wipe everything
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

    asyncio.run(_manage())


# =============================================================================
#  Internal helpers
# =============================================================================

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
                sem = asyncio.Semaphore(concurrency)

                async def _one(u: str):
                    async with sem:
                        r = await scanner.scan_url(u, **scan_kwargs)
                        progress.advance(task)
                        return r

                return await asyncio.gather(*[_one(u) for u in urls])


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
