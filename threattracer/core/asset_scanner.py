"""
threattracer.core.asset_scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Asset-based vulnerability scanning.

Workflow:
  1. Fetch target URL (follow redirects, grab headers/body)
  2. Fingerprint technologies via python-Wappalyzer + header heuristics
  3. For each detected technology with a version:
       → CPE search → CVE lookup → Exploit/PoC/KEV/Nuclei/MSF enrichment
  4. Return AssetScanResult with per-tech CVE results

Supports:
  - Single URL:  threattracer asset https://example.com
  - Batch URLs:  threattracer asset --file targets.txt
  - Concurrency: --concurrency N
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, Optional
from urllib.parse import urlparse

from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig
from threattracer.utils.http_client import AsyncHTTPClient
from threattracer.utils.models import (
    AssetScanResult,
    ComponentCVEResult,
    DetectedTech,
)

log = logging.getLogger(__name__)

# ── Header-based fingerprinting signatures ─────────────────────────────────
# Format: header_name → {pattern → (tech_name, version_group_or_None)}
_HEADER_SIGS: list[dict] = [
    {"header": "server",          "pattern": r"Apache/([\d.]+)",       "tech": "Apache HTTP Server"},
    {"header": "server",          "pattern": r"nginx/([\d.]+)",         "tech": "nginx"},
    {"header": "server",          "pattern": r"Microsoft-IIS/([\d.]+)", "tech": "Microsoft IIS"},
    {"header": "server",          "pattern": r"LiteSpeed",              "tech": "LiteSpeed"},
    {"header": "server",          "pattern": r"Jetty/([\d.]+)",         "tech": "Jetty"},
    {"header": "server",          "pattern": r"Tomcat/([\d.]+)",        "tech": "Apache Tomcat"},
    {"header": "server",          "pattern": r"OpenSSL/([\d.]+)",       "tech": "OpenSSL"},
    {"header": "x-powered-by",    "pattern": r"PHP/([\d.]+)",           "tech": "PHP"},
    {"header": "x-powered-by",    "pattern": r"ASP\.NET",               "tech": "ASP.NET"},
    {"header": "x-powered-by",    "pattern": r"Express",                "tech": "Express"},
    {"header": "x-powered-by",    "pattern": r"Next\.js",               "tech": "Next.js"},
    {"header": "x-generator",     "pattern": r"(WordPress)[\s/]*([\d.]*)", "tech": "WordPress", "ver_group": 2},
    {"header": "x-drupal-cache",  "pattern": r".",                      "tech": "Drupal"},
    {"header": "x-joomla-token",  "pattern": r".",                      "tech": "Joomla"},
    {"header": "x-aspnet-version","pattern": r"([\d.]+)",               "tech": "ASP.NET"},
    {"header": "x-runtime",       "pattern": r"Ruby/([\d.]+)",          "tech": "Ruby on Rails"},
    {"header": "x-content-type-options", "pattern": r".", "tech": None},   # info only
]

# Body-based signatures (regex on HTML)
_BODY_SIGS: list[dict] = [
    {"pattern": r'wp-content|wp-includes',                "tech": "WordPress"},
    {"pattern": r'Joomla!|joomla\.org',                    "tech": "Joomla"},
    {"pattern": r'drupal\.org|Drupal',                     "tech": "Drupal"},
    {"pattern": r'laravel\.com|Laravel',                   "tech": "Laravel"},
    {"pattern": r'Django|django-admin',                    "tech": "Django"},
    {"pattern": r'Spring Framework|springmvc',             "tech": "Spring Framework"},
    {"pattern": r'struts\.apache|Struts',                  "tech": "Apache Struts"},
    {"pattern": r'SharePoint|Microsoft SharePoint',        "tech": "Microsoft SharePoint"},
    {"pattern": r'Confluence',                             "tech": "Atlassian Confluence"},
    {"pattern": r'JIRA|Atlassian Jira',                    "tech": "Atlassian Jira"},
    {"pattern": r'Jenkins',                                "tech": "Jenkins"},
    {"pattern": r'GitLab',                                 "tech": "GitLab"},
    {"pattern": r'Grafana',                                "tech": "Grafana"},
    {"pattern": r'Apache Solr|/solr/',                     "tech": "Apache Solr"},
    {"pattern": r'Elasticsearch',                          "tech": "Elasticsearch"},
]


def _fingerprint_headers(headers: dict) -> List[DetectedTech]:
    techs: dict[str, DetectedTech] = {}
    h_lower = {k.lower(): v for k, v in headers.items()}

    for sig in _HEADER_SIGS:
        if sig["tech"] is None:
            continue
        header_val = h_lower.get(sig["header"], "")
        if not header_val:
            continue
        m = re.search(sig["pattern"], header_val, re.IGNORECASE)
        if m:
            ver_group = sig.get("ver_group", 1)
            try:
                version = m.group(ver_group) if m.lastindex and m.lastindex >= ver_group else None
            except IndexError:
                version = None
            name = sig["tech"]
            if name not in techs:
                techs[name] = DetectedTech(name=name, version=version or None, confidence=95)

    return list(techs.values())


def _fingerprint_body(body: str) -> List[DetectedTech]:
    techs: dict[str, DetectedTech] = {}
    for sig in _BODY_SIGS:
        if re.search(sig["pattern"], body[:50_000], re.IGNORECASE):
            name = sig["tech"]
            if name not in techs:
                techs[name] = DetectedTech(name=name, confidence=60)
    return list(techs.values())


def _merge_techs(
    header_techs: List[DetectedTech],
    body_techs: List[DetectedTech],
    wappalyzer_techs: List[DetectedTech],
) -> List[DetectedTech]:
    """Merge, deduplicate, and prefer version-carrying entries."""
    merged: dict[str, DetectedTech] = {}

    for t in wappalyzer_techs + header_techs + body_techs:
        key = t.name.lower()
        if key not in merged:
            merged[key] = t
        else:
            existing = merged[key]
            # Prefer entry with a version
            if t.version and not existing.version:
                merged[key] = t
            # Prefer higher confidence
            elif t.confidence > existing.confidence and not existing.version:
                merged[key] = t

    return sorted(merged.values(), key=lambda t: -t.confidence)


async def _run_wappalyzer(url: str, timeout: int) -> List[DetectedTech]:
    """
    Run python-Wappalyzer in a thread (it uses sync requests internally).
    Returns empty list if Wappalyzer is not installed or fails.
    """
    try:
        import asyncio
        from concurrent.futures import ThreadPoolExecutor

        def _sync_wappalyze() -> List[DetectedTech]:
            from Wappalyzer import Wappalyzer, WebPage
            import warnings
            warnings.filterwarnings("ignore")
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(url, verify=False, timeout=timeout)
            raw = wappalyzer.analyze_with_versions_and_categories(webpage)
            results: List[DetectedTech] = []
            for name, info in raw.items():
                versions = info.get("versions", [])
                cats = list(info.get("categories", {}).values()) if isinstance(info.get("categories"), dict) else []
                results.append(DetectedTech(
                    name=name,
                    version=versions[0] if versions else None,
                    categories=cats,
                    confidence=90,
                ))
            return results

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            return await asyncio.wait_for(
                loop.run_in_executor(pool, _sync_wappalyze),
                timeout=timeout + 5,
            )
    except ImportError:
        log.debug("python-Wappalyzer not installed — using header/body fingerprinting only")
        return []
    except Exception as exc:
        log.debug("Wappalyzer failed for %s: %s", url, exc)
        return []


class AssetScanner:
    """Fingerprints a URL and runs CVE lookups for each detected technology."""

    def __init__(
        self,
        config: AppConfig,
        http: AsyncHTTPClient,
        cache: ResponseCache,
    ) -> None:
        self._cfg = config
        self._http = http
        self._cache = cache

    async def scan_url(
        self,
        url: str,
        include_exploits: bool = True,
        include_pocs: bool = True,
        enrich_epss: bool = True,
        include_kev: bool = True,
        include_nuclei: bool = True,
        include_msf: bool = True,
        min_confidence: int = 50,
    ) -> AssetScanResult:
        """
        Full pipeline: fingerprint → CVE lookup → enrichment.
        Returns an AssetScanResult.
        """
        from threattracer.core.scanner import Scanner

        log.info("Asset scan: %s", url)
        result = AssetScanResult(url=url)

        # ── Step 1: Fetch the URL ──────────────────────────────────────
        try:
            resp = await self._http._client.get(  # type: ignore[union-attr]
                url,
                follow_redirects=True,
                timeout=self._cfg.wappalyzer_timeout,
            )
            result.final_url = str(resp.url)
            result.status_code = resp.status_code
            result.server = resp.headers.get("server")
            headers = dict(resp.headers)
            body = resp.text
        except Exception as exc:
            result.error = str(exc)
            log.warning("Failed to fetch %s: %s", url, exc)
            return result

        # ── Step 2: Fingerprint ────────────────────────────────────────
        header_techs = _fingerprint_headers(headers)
        body_techs = _fingerprint_body(body)
        wappalyzer_techs = await _run_wappalyzer(url, self._cfg.wappalyzer_timeout)

        all_techs = _merge_techs(header_techs, body_techs, wappalyzer_techs)
        # Only keep techs with sufficient confidence
        result.technologies = [t for t in all_techs if t.confidence >= min_confidence]

        if not result.technologies:
            log.info("No technologies detected for %s", url)
            return result

        log.info(
            "Detected %d technologies on %s: %s",
            len(result.technologies),
            url,
            [f"{t.name} {t.version or ''}" for t in result.technologies],
        )

        # ── Step 3: CVE lookup for each tech with a version ────────────
        async with Scanner(self._cfg) as scanner:
            # Inject the already-open http/cache into scanner to avoid
            # opening new connections — Scanner manages its own for simplicity.
            cve_tasks = []
            versioned = [t for t in result.technologies if t.version]

            for tech in versioned:
                cve_tasks.append(
                    self._scan_tech(
                        scanner,
                        tech,
                        include_exploits,
                        include_pocs,
                        enrich_epss,
                        include_kev,
                        include_nuclei,
                        include_msf,
                    )
                )

            cve_results = await asyncio.gather(*cve_tasks, return_exceptions=True)
            for res in cve_results:
                if isinstance(res, ComponentCVEResult):
                    result.cve_results.append(res)
                elif isinstance(res, Exception):
                    log.warning("CVE task error: %s", res)

        return result

    async def _scan_tech(
        self,
        scanner,
        tech: DetectedTech,
        include_exploits: bool,
        include_pocs: bool,
        enrich_epss: bool,
        include_kev: bool,
        include_nuclei: bool,
        include_msf: bool,
    ) -> ComponentCVEResult:
        from threattracer.core.scanner import ScanResult

        log.info("Scanning CVEs for %s %s", tech.name, tech.version)
        scan_result: ScanResult = await scanner.scan_component(
            component=tech.name,
            version=tech.version or "",
            include_exploits=include_exploits,
            include_pocs=include_pocs,
            enrich_epss=enrich_epss,
            include_kev=include_kev,
            include_nuclei=include_nuclei,
            include_msf=include_msf,
        )

        return ComponentCVEResult(
            tech=tech,
            cpe_matches=scan_result.cpes_found,
            records=scan_result.cve_records,
        )

    async def scan_urls(
        self,
        urls: List[str],
        concurrency: int = 5,
        **kwargs,
    ) -> List[AssetScanResult]:
        """
        Scan multiple URLs concurrently.
        Respects concurrency limit to avoid hammering targets.
        """
        sem = asyncio.Semaphore(concurrency)

        async def _bounded(url: str) -> AssetScanResult:
            async with sem:
                return await self.scan_url(url, **kwargs)

        tasks = [_bounded(u) for u in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)
