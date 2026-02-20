"""
threattracer.core.msf_check
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Metasploit module discovery for CVEs.

For pentesters: MSF module = immediate weaponisation potential.

Strategy:
  1. Download/cache the Metasploit modules metadata JSON from rapid7/metasploit-framework
  2. Search for the CVE ID in the references field
  3. Return module name, type, and description
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig
from threattracer.utils.http_client import AsyncHTTPClient
from threattracer.utils.models import MSFModule

log = logging.getLogger(__name__)


class MSFCheckClient:
    """Searches Metasploit module index for CVE references."""

    def __init__(
        self,
        config: AppConfig,
        http: AsyncHTTPClient,
        cache: ResponseCache,
    ) -> None:
        self._cfg = config
        self._http = http
        self._cache = cache
        # cve_id (lowercase) → list of module dicts
        self._index: Optional[Dict[str, List[dict]]] = None

    async def _ensure_index(self) -> None:
        if self._index is not None:
            return

        cache_key = "msf:module_index"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            self._index = cached
            log.debug("MSF index loaded from cache")
            return

        log.info("Downloading Metasploit module metadata...")
        data = await self._http.get(self._cfg.msf_index_url)
        if not data:
            log.warning("Failed to download MSF module metadata")
            self._index = {}
            return

        # Build an inverted index: cve_id → [module, ...]
        inverted: Dict[str, List[dict]] = {}
        for mod_path, mod in data.items():
            refs = mod.get("references", [])
            for ref in refs:
                # refs look like ["CVE", "2021-44228"] or ["URL", "..."]
                if isinstance(ref, list) and len(ref) == 2 and ref[0] == "CVE":
                    cve_key = f"cve-{ref[1]}".lower()
                    if cve_key not in inverted:
                        inverted[cve_key] = []
                    inverted[cve_key].append({
                        "path": mod_path,
                        "name": mod.get("name", mod_path),
                        "description": mod.get("description", ""),
                        "type": mod_path.split("/")[0] if "/" in mod_path else "exploit",
                    })

        self._index = inverted
        log.info("MSF index built: %d CVEs referenced", len(self._index))
        await self._cache.set(cache_key, self._index)

    async def find_modules(self, cve_id: str) -> List[MSFModule]:
        """Return Metasploit modules for a CVE ID."""
        await self._ensure_index()
        if not self._index:
            return []

        # Normalise: CVE-2021-44228 → cve-2021-44228
        key = cve_id.lower()
        modules = self._index.get(key, [])
        return [
            MSFModule(
                name=m["name"],
                fullname=m["path"],
                description=m["description"][:200],
                module_type=m["type"],
            )
            for m in modules
        ]

    async def enrich_records(self, records: list) -> None:
        """Mutate CVERecord list in-place with MSF module info."""
        import asyncio
        await self._ensure_index()
        tasks = [self.find_modules(r.cve_id) for r in records]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for record, result in zip(records, results):
            if isinstance(result, list):
                record.msf_modules = result
