"""
threattracer.core.nuclei_check
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nuclei template discovery for CVEs.

Nuclei templates are ready-to-fire test cases.
For pentesters: finding a Nuclei template means "one command away from confirmation."

Strategy:
  1. Fetch ProjectDiscovery nuclei-templates CVE index
  2. Match by CVE ID in template file names
  3. Return clickable GitHub links + raw template URLs
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig
from threattracer.utils.http_client import AsyncHTTPClient
from threattracer.utils.models import NucleiTemplate

log = logging.getLogger(__name__)

# The nuclei-templates CVE directory listing on GitHub API
_NUCLEI_CVE_API = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves"
_NUCLEI_RAW_BASE = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves"
_NUCLEI_BROWSE_BASE = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves"


class NucleiCheckClient:
    """Checks if Nuclei templates exist for given CVEs."""

    def __init__(
        self,
        config: AppConfig,
        http: AsyncHTTPClient,
        cache: ResponseCache,
    ) -> None:
        self._cfg = config
        self._http = http
        self._cache = cache
        # year → list of template filenames in that year folder
        self._year_index: Dict[str, List[str]] = {}

    def _gh_headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json"}
        if self._cfg.github_token:
            h["Authorization"] = f"Bearer {self._cfg.github_token}"
        return h

    async def _get_year_listing(self, year: str) -> List[str]:
        """Return list of template file names for a given year."""
        if year in self._year_index:
            return self._year_index[year]

        cache_key = f"nuclei:year:{year}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            self._year_index[year] = cached
            return cached

        data = await self._http.get(
            f"{_NUCLEI_CVE_API}/{year}",
            extra_headers=self._gh_headers(),
        )
        if not data or not isinstance(data, list):
            self._year_index[year] = []
            return []

        names = [item["name"] for item in data if item.get("type") == "file"]
        self._year_index[year] = names
        # Cache year index for 24h (changes infrequently)
        await self._cache.set(cache_key, names)
        return names

    async def find_templates(self, cve_id: str) -> List[NucleiTemplate]:
        """Return all Nuclei templates for a CVE ID."""
        cache_key = f"nuclei:cve:{cve_id}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return [NucleiTemplate(**t) for t in cached]

        year = cve_id.split("-")[1]
        filenames = await self._get_year_listing(year)

        cve_lower = cve_id.lower()
        matched: List[NucleiTemplate] = []
        for fname in filenames:
            if cve_lower in fname.lower():
                template_id = fname.replace(".yaml", "")
                raw_url = f"{_NUCLEI_RAW_BASE}/{year}/{fname}"
                browse_url = f"{_NUCLEI_BROWSE_BASE}/{year}/{fname}"

                # Fetch the template to extract name/severity/tags
                meta = await self._parse_template_meta(raw_url)

                matched.append(
                    NucleiTemplate(
                        template_id=template_id,
                        name=meta.get("name", template_id),
                        severity=meta.get("severity", "unknown"),
                        url=browse_url,
                        tags=meta.get("tags", []),
                    )
                )

        await self._cache.set(cache_key, [t.model_dump() for t in matched])
        return matched

    async def _parse_template_meta(self, raw_url: str) -> dict:
        """Quick regex parse of a nuclei template's info block."""
        text = await self._http.get_text(raw_url)
        if not text:
            return {}
        meta: dict = {}
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("name:"):
                meta["name"] = line.split("name:", 1)[1].strip().strip('"')
            elif line.startswith("severity:"):
                meta["severity"] = line.split("severity:", 1)[1].strip()
            elif line.startswith("tags:"):
                raw_tags = line.split("tags:", 1)[1].strip()
                meta["tags"] = [t.strip() for t in raw_tags.split(",")]
            if len(meta) == 3:
                break
        return meta

    async def enrich_records(self, records: list) -> None:
        """Mutate CVERecord list in-place with Nuclei template info."""
        import asyncio
        tasks = [self.find_templates(r.cve_id) for r in records]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for record, result in zip(records, results):
            if isinstance(result, list):
                record.nuclei_templates = result
