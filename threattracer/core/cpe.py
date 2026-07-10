"""
threattracer.core.cpe
~~~~~~~~~~~~~~~~~~~~~
CPE discovery and smart ranking.

Features:
  - NVD CPE search API
  - rapidfuzz-based similarity scoring
  - Vendor normalisation
  - Version-range awareness
  - Returns ranked CPEMatch list (best first)
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from rapidfuzz import fuzz

from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig
from threattracer.utils.http_client import AsyncHTTPClient
from threattracer.utils.models import CPEMatch

log = logging.getLogger(__name__)

# Common vendor name normalisations
_VENDOR_MAP: dict[str, str] = {
    "apache": "apache",
    "apache software foundation": "apache",
    "microsoft": "microsoft",
    "ms": "microsoft",
    "google": "google",
    "alphabet": "google",
    "oracle": "oracle",
    "sun microsystems": "oracle",
    "canonical": "canonical",
    "ubuntu": "canonical",
    "nginx": "nginx",
    "f5": "f5",
    "cisco": "cisco",
    "wordpress": "wordpress",
    "automattic": "wordpress",
    "php": "php",
    "the php group": "php",
    "openssl": "openssl",
    "openssh": "openbsd",
    "redhat": "redhat",
    "red hat": "redhat",
}


def _normalise_vendor(name: str) -> str:
    lower = name.lower().strip()
    return _VENDOR_MAP.get(lower, lower)


def _cpe_title(cpe_name: str) -> str:
    """Extract a human-readable component from the CPE URI."""
    parts = cpe_name.split(":")
    # cpe:2.3:a:vendor:product:version:...
    if len(parts) >= 5:
        return f"{parts[3]} {parts[4]} {parts[5] if len(parts) > 5 else ''}".strip()
    return cpe_name


def _score_cpe(cpe_name: str, component: str, version: str) -> float:
    """
    Score a CPE against the query using rapidfuzz.
    Returns 0–100 float.
    """
    normalised_component = _normalise_vendor(component)
    cpe_lower = cpe_name.lower()
    title = _cpe_title(cpe_name).lower()

    # Partial ratio between component/version and the CPE title
    comp_score = fuzz.token_set_ratio(normalised_component, title)
    # Bonus if exact version appears in CPE
    ver_bonus = 20.0 if version and version.lower() in cpe_lower else 0.0
    # Penalty for wildcard-heavy CPEs (less specific)
    wildcard_count = cpe_name.count(":*")
    specificity_penalty = wildcard_count * 2.0

    return max(0.0, comp_score + ver_bonus - specificity_penalty)


class CPEClient:
    """Async NVD CPE search with smart ranking."""

    def __init__(
        self,
        config: AppConfig,
        http: AsyncHTTPClient,
        cache: ResponseCache,
    ) -> None:
        self._cfg = config
        self._http = http
        self._cache = cache

    async def search(
        self,
        component: str,
        version: str,
        top_n: int = 10,
    ) -> List[CPEMatch]:
        """
        Search NVD for CPEs matching component+version.
        Returns the top_n best-matching CPEs, scored by similarity.
        """
        keyword = f"{component} {version}"
        cache_key = f"cpe:search:{keyword.lower()}"

        cached = await self._cache.get(cache_key)
        raw_products: list
        if cached is not None:
            log.debug("Cache hit: %s", cache_key)
            raw_products = cached
        else:
            data = await self._http.get(
                self._cfg.nvd_cpe_endpoint,
                params={"keywordSearch": keyword, "resultsPerPage": 100},
            )
            if data is None:
                return []
            raw_products = data.get("products", [])
            await self._cache.set(cache_key, raw_products)

        matches: List[CPEMatch] = []
        for item in raw_products:
            cpe_info = item.get("cpe", {})
            cpe_name: str = cpe_info.get("cpeName", "")
            if not cpe_name:
                continue

            # Grab human title if NVD provides one
            titles = cpe_info.get("titles", [])
            title = next(
                (t["title"] for t in titles if t.get("lang") == "en"),
                _cpe_title(cpe_name),
            )

            score = _score_cpe(cpe_name, component, version)
            matches.append(CPEMatch(cpe_name=cpe_name, title=title, match_score=score))

        # Sort best → worst
        matches.sort(key=lambda m: m.match_score, reverse=True)
        return matches[:top_n]

    async def version_range_cpes(
        self,
        component: str,
        version: str,
        top_n: int = 5,
    ) -> List[str]:
        """
        Return raw CPE strings, deduplicated across minor version variants.
        Useful when callers want to query CVEs by CPE.
        """
        matches = await self.search(component, version, top_n=top_n)
        seen_products: set[str] = set()
        result: List[str] = []
        for m in matches:
            parts = m.cpe_name.split(":")
            # Dedup by vendor:product pair
            if len(parts) >= 5:
                vp = f"{parts[3]}:{parts[4]}"
                if vp in seen_products:
                    continue
                seen_products.add(vp)
            result.append(m.cpe_name)
        return result
