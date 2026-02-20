"""
threattracer.core.kev
~~~~~~~~~~~~~~~~~~~~~
CISA Known Exploited Vulnerabilities (KEV) Catalog integration.

The KEV catalog is the gold-standard signal that a vulnerability is:
  - Actively exploited in the wild
  - High-priority for patching (CISA Binding Operational Directive 22-01)

For pentesters: KEV = confirmed real-world exploitation = prioritise.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig
from threattracer.utils.http_client import AsyncHTTPClient

log = logging.getLogger(__name__)

# KEV entry shape:
# {
#   "cveID": "CVE-2021-44228",
#   "vendorProject": "Apache",
#   "product": "Log4j",
#   "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
#   "dateAdded": "2021-12-10",
#   "shortDescription": "...",
#   "requiredAction": "...",
#   "dueDate": "2021-12-24",
#   "knownRansomwareCampaignUse": "Known"
# }


class KEVClient:
    """Downloads, caches, and queries the CISA KEV catalog."""

    def __init__(
        self,
        config: AppConfig,
        http: AsyncHTTPClient,
        cache: ResponseCache,
    ) -> None:
        self._cfg = config
        self._http = http
        self._cache = cache
        self._index: Optional[Dict[str, dict]] = None

    async def _ensure_index(self) -> None:
        if self._index is not None:
            return

        cache_key = "kev:catalog"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            self._index = cached
            log.debug("KEV catalog loaded from cache (%d entries)", len(self._index))
            return

        log.info("Downloading CISA KEV catalog...")
        data = await self._http.get(self._cfg.kev_url)
        if not data:
            log.warning("Failed to download CISA KEV catalog")
            self._index = {}
            return

        self._index = {
            entry["cveID"]: entry
            for entry in data.get("vulnerabilities", [])
        }
        log.info("CISA KEV catalog loaded: %d entries", len(self._index))
        await self._cache.set(cache_key, self._index)

    async def is_in_kev(self, cve_id: str) -> Optional[dict]:
        """
        Return the KEV entry if this CVE is in the catalog, else None.
        The returned dict contains dateAdded, knownRansomwareCampaignUse, etc.
        """
        await self._ensure_index()
        return (self._index or {}).get(cve_id)

    async def enrich_records(self, records: list) -> None:
        """
        Mutate CVERecord list in-place with KEV status.
        Single bulk call to the index — no per-CVE network traffic.
        """
        await self._ensure_index()
        if not self._index:
            return

        for record in records:
            entry = self._index.get(record.cve_id)
            if entry:
                record.in_kev = True
                record.kev_date_added = entry.get("dateAdded")
                record.kev_ransomware_use = entry.get("knownRansomwareCampaignUse")
                log.debug("KEV hit: %s", record.cve_id)
