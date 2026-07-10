"""
threattracer.core.scanner
~~~~~~~~~~~~~~~~~~~~~~~~~
Async orchestrator — the single public API for all scan types.
Wires together: NVD, CPE, ExploitDB, GitHub PoC, CISA KEV, Nuclei, MSF.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional

from threattracer.core.cpe import CPEClient
from threattracer.core.exploitdb import ExploitDBClient
from threattracer.core.github_poc import GitHubPoCClient
from threattracer.core.kev import KEVClient
from threattracer.core.msf_check import MSFCheckClient
from threattracer.core.nuclei_check import NucleiCheckClient
from threattracer.core.nvd import NVDClient
from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig
from threattracer.utils.http_client import AsyncHTTPClient
from threattracer.utils.models import CVERecord, CPEMatch, Severity, SEVERITY_ORDER

log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    cpes_found: List[CPEMatch] = field(default_factory=list)
    cve_records: List[CVERecord] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.cve_records)

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.cve_records if r.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for r in self.cve_records if r.severity == Severity.HIGH)

    @property
    def exploit_count(self) -> int:
        return sum(1 for r in self.cve_records if r.has_exploit)

    @property
    def kev_count(self) -> int:
        return sum(1 for r in self.cve_records if r.in_kev)

    @property
    def nuclei_count(self) -> int:
        return sum(1 for r in self.cve_records if r.nuclei_templates)

    @property
    def msf_count(self) -> int:
        return sum(1 for r in self.cve_records if r.msf_modules)

    @property
    def weaponised_count(self) -> int:
        return sum(1 for r in self.cve_records if r.weaponised)


class Scanner:
    """
    Async vulnerability scanner context manager.

    Usage::

        async with Scanner(config) as scanner:
            result = await scanner.scan_component("apache", "2.4.51")
    """

    def __init__(self, config: AppConfig) -> None:
        self._cfg = config
        self._http: Optional[AsyncHTTPClient] = None
        self._cache: Optional[ResponseCache] = None
        self._nvd: Optional[NVDClient] = None
        self._cpe: Optional[CPEClient] = None
        self._edb: Optional[ExploitDBClient] = None
        self._poc: Optional[GitHubPoCClient] = None
        self._kev: Optional[KEVClient] = None
        self._nuclei: Optional[NucleiCheckClient] = None
        self._msf: Optional[MSFCheckClient] = None

    async def __aenter__(self) -> "Scanner":
        self._http = AsyncHTTPClient(self._cfg)
        await self._http.__aenter__()
        self._cache = ResponseCache(self._cfg)
        await self._cache.__aenter__()

        self._nvd    = NVDClient(self._cfg, self._http, self._cache)
        self._cpe    = CPEClient(self._cfg, self._http, self._cache)
        self._edb    = ExploitDBClient(self._cfg, self._http, self._cache)
        self._poc    = GitHubPoCClient(self._cfg, self._http, self._cache)
        self._kev    = KEVClient(self._cfg, self._http, self._cache)
        self._nuclei = NucleiCheckClient(self._cfg, self._http, self._cache)
        self._msf    = MSFCheckClient(self._cfg, self._http, self._cache)
        return self

    async def __aexit__(self, *_) -> None:
        if self._http:
            await self._http.__aexit__()
        if self._cache:
            await self._cache.__aexit__()

    # ── Public scan methods ────────────────────────────────────────────

    async def scan_component(
        self,
        component: str,
        version: str,
        include_exploits: bool = True,
        include_pocs: bool = True,
        enrich_epss: bool = True,
        include_kev: bool = True,
        include_nuclei: bool = True,
        include_msf: bool = True,
        top_cpes: int = 5,
    ) -> ScanResult:
        assert self._cpe and self._nvd

        log.info("CPE search: %s %s", component, version)
        cpe_matches = await self._cpe.search(component, version, top_n=top_cpes)
        if not cpe_matches:
            return ScanResult()

        cve_batches = await asyncio.gather(
            *[self._nvd.fetch_by_cpe(m.cpe_name) for m in cpe_matches]
        )
        records = _dedup_records([r for batch in cve_batches for r in batch])
        await self._enrich(records, include_exploits, include_pocs, enrich_epss,
                           include_kev, include_nuclei, include_msf)
        return ScanResult(cpes_found=cpe_matches, cve_records=records)

    async def scan_cpe(
        self,
        cpe_string: str,
        include_exploits: bool = True,
        include_pocs: bool = True,
        enrich_epss: bool = True,
        include_kev: bool = True,
        include_nuclei: bool = True,
        include_msf: bool = True,
    ) -> ScanResult:
        assert self._nvd
        records = await self._nvd.fetch_by_cpe(cpe_string)
        await self._enrich(records, include_exploits, include_pocs, enrich_epss,
                           include_kev, include_nuclei, include_msf)
        return ScanResult(cve_records=records)

    async def scan_cve(
        self,
        cve_id: str,
        include_exploits: bool = True,
        include_pocs: bool = True,
        enrich_epss: bool = True,
        include_kev: bool = True,
        include_nuclei: bool = True,
        include_msf: bool = True,
    ) -> ScanResult:
        assert self._nvd
        records = await self._nvd.fetch_by_cve_id(cve_id)
        await self._enrich(records, include_exploits, include_pocs, enrich_epss,
                           include_kev, include_nuclei, include_msf)
        return ScanResult(cve_records=records)

    # ── Enrichment ─────────────────────────────────────────────────────

    async def _enrich(
        self,
        records: List[CVERecord],
        include_exploits: bool,
        include_pocs: bool,
        enrich_epss: bool,
        include_kev: bool,
        include_nuclei: bool,
        include_msf: bool,
    ) -> None:
        tasks = []
        if include_exploits:
            tasks.append(self._attach_exploits(records))
        if include_pocs:
            tasks.append(self._attach_pocs(records))
        if enrich_epss:
            tasks.append(self._nvd.enrich_with_epss(records))   # type: ignore
        if include_kev:
            tasks.append(self._kev.enrich_records(records))      # type: ignore
        if include_nuclei:
            tasks.append(self._nuclei.enrich_records(records))   # type: ignore
        if include_msf:
            tasks.append(self._msf.enrich_records(records))      # type: ignore

        await asyncio.gather(*tasks)

    async def _attach_exploits(self, records: List[CVERecord]) -> None:
        assert self._edb
        results = await asyncio.gather(
            *[self._edb.search_by_cve(r.cve_id) for r in records]
        )
        for record, exploits in zip(records, results):
            record.exploits = exploits

    async def _attach_pocs(self, records: List[CVERecord]) -> None:
        assert self._poc
        results = await asyncio.gather(
            *[self._poc.find_pocs(r.cve_id) for r in records]
        )
        for record, pocs in zip(records, results):
            record.pocs = pocs


def _dedup_records(records: List[CVERecord]) -> List[CVERecord]:
    seen: set[str] = set()
    out: List[CVERecord] = []
    for r in records:
        if r.cve_id not in seen:
            seen.add(r.cve_id)
            out.append(r)
    return out


def sort_records(records: List[CVERecord], sort_by: str = "cvss") -> List[CVERecord]:
    if sort_by == "epss":
        return sorted(records, key=lambda r: r.epss_score or 0.0, reverse=True)
    if sort_by == "published":
        return sorted(records, key=lambda r: r.published or "", reverse=True)
    if sort_by == "kev":
        return sorted(records, key=lambda r: (not r.in_kev, -(r.cvss_score or 0.0)))
    # Default: severity (critical first), then CVSS score
    return sorted(
        records,
        key=lambda r: (SEVERITY_ORDER.get(r.severity, 99), -(r.cvss_score or 0.0)),
    )
