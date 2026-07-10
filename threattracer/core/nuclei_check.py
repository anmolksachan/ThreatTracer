"""
threattracer.core.nuclei_check
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nuclei template discovery for CVEs.

Nuclei templates are ready-to-run *detection* checks — for an authorised tester
they mean "one command away from safely confirming exposure."

Strategy:
  1. List the per-year folder of ProjectDiscovery's nuclei-templates via the
     GitHub Contents API (cached; a GitHub token raises the rate limit).
  2. Match template filenames against the CVE ID.
  3. Optionally fetch each matched template's YAML to extract name/severity/tags
     (bounded concurrency; controlled by config.nuclei_fetch_meta).

Every step degrades gracefully: no token, a 403/404, or a network error yields
an empty result rather than an exception.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List

from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig
from threattracer.utils.http_client import AsyncHTTPClient
from threattracer.utils.models import NucleiTemplate
from threattracer.utils.validate import cve_year, is_valid_cve

log = logging.getLogger(__name__)


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
        # year -> list of template filenames in that year folder
        self._year_index: Dict[str, List[str]] = {}
        # serialise year-listing fetches so concurrent CVEs in the same year
        # don't each hit the GitHub API
        self._year_lock = asyncio.Lock()

    def _gh_headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json"}
        if self._cfg.github_token:
            h["Authorization"] = f"Bearer {self._cfg.github_token}"
        return h

    async def _get_year_listing(self, year: str) -> List[str]:
        """Return the list of template file names for a given year (cached)."""
        if year in self._year_index:
            return self._year_index[year]

        async with self._year_lock:
            if year in self._year_index:      # re-check inside the lock
                return self._year_index[year]

            cache_key = f"nuclei:year:{year}"
            cached = await self._cache.get(cache_key)
            if cached is not None:
                self._year_index[year] = cached
                return cached

            data = await self._http.get(
                f"{self._cfg.nuclei_contents_api}/{year}",
                extra_headers=self._gh_headers(),
            )
            if not data or not isinstance(data, list):
                # 403 (rate limit), 404 (no such year), or network error
                self._year_index[year] = []
                return []

            names = [
                item["name"]
                for item in data
                if isinstance(item, dict) and item.get("type") == "file"
                and item.get("name", "").endswith((".yaml", ".yml"))
            ]
            self._year_index[year] = names
            await self._cache.set(cache_key, names)
            return names

    async def find_templates(self, cve_id: str) -> List[NucleiTemplate]:
        """Return all Nuclei templates for a CVE ID."""
        if not is_valid_cve(cve_id):
            return []

        cache_key = f"nuclei:cve:{cve_id}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return [NucleiTemplate(**t) for t in cached]

        year = cve_year(cve_id)
        if not year:
            return []

        filenames = await self._get_year_listing(year)
        cve_lower = cve_id.lower()
        matched_files = [f for f in filenames if cve_lower in f.lower()]

        matched: List[NucleiTemplate] = []
        for fname in matched_files:
            template_id = fname.rsplit(".", 1)[0]
            raw_url = f"{self._cfg.nuclei_raw_base}/{year}/{fname}"
            browse_url = f"{self._cfg.nuclei_browse_base}/{year}/{fname}"

            meta: dict = {}
            if self._cfg.nuclei_fetch_meta:
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
        """Quick, best-effort parse of a nuclei template's info block."""
        try:
            text = await self._http.get_text(raw_url)
        except Exception as exc:  # never let a template fetch break a scan
            log.debug("nuclei meta fetch failed for %s: %s", raw_url, exc)
            return {}
        if not text:
            return {}
        meta: dict = {}
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("name:") and "name" not in meta:
                meta["name"] = stripped.split("name:", 1)[1].strip().strip('"\'')
            elif stripped.startswith("severity:") and "severity" not in meta:
                meta["severity"] = stripped.split("severity:", 1)[1].strip()
            elif stripped.startswith("tags:") and "tags" not in meta:
                raw_tags = stripped.split("tags:", 1)[1].strip()
                meta["tags"] = [t.strip() for t in raw_tags.split(",") if t.strip()]
            if len(meta) == 3:
                break
        return meta

    async def enrich_records(self, records: list) -> None:
        """Mutate CVERecord list in-place with Nuclei template info (bounded)."""
        if not records:
            return
        sem = asyncio.Semaphore(max(1, self._cfg.nuclei_meta_concurrency))

        async def _one(rec):
            async with sem:
                return await self.find_templates(rec.cve_id)

        results = await asyncio.gather(
            *[_one(r) for r in records], return_exceptions=True
        )
        for record, result in zip(records, results):
            if isinstance(result, list):
                record.nuclei_templates = result
            elif isinstance(result, Exception):
                log.debug("nuclei enrich error for %s: %s", record.cve_id, result)
