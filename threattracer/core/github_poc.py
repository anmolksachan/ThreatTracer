"""
threattracer.core.github_poc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PoC discovery from multiple sources:
  1. Trickest CVE mirror  (no auth, very reliable)
  2. GitHub Search API    (optional token, ranked by stars, forks filtered)
  3. Vulhub               (Docker-based PoC environments)
  4. PacketStorm          (search link)
  5. Sploitus             (aggregated exploit search link)

All real HTTP results are cached. URLs are cleaned and validated.
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import urlparse

from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig
from threattracer.utils.http_client import AsyncHTTPClient
from threattracer.utils.models import PoCReference

log = logging.getLogger(__name__)

# Matches GitHub URLs — stops at whitespace, ), ], or markdown link chars
_GH_URL_RE = re.compile(r"https://github\.com/[\w\-./]+")
_GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
_GITHUB_CODE_SEARCH_URL = "https://api.github.com/search/code"

# Known junk/meta URLs to skip in trickest output
_SKIP_URLS = {
    "https://github.com/trickest/cve",
    "https://github.com/trickest",
}


def _clean_github_url(url: str) -> str:
    """Strip trailing markdown punctuation that regex may capture."""
    return url.rstrip(".,);'\"`")


def _is_valid_poc_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.netloc != "github.com":
        return False
    parts = parsed.path.strip("/").split("/")
    # Must have at least owner/repo
    if len(parts) < 2:
        return False
    if url in _SKIP_URLS:
        return False
    return True


class GitHubPoCClient:
    """Discovers PoC repositories and references for a CVE."""

    def __init__(
        self,
        config: AppConfig,
        http: AsyncHTTPClient,
        cache: ResponseCache,
    ) -> None:
        self._cfg = config
        self._http = http
        self._cache = cache

    async def find_pocs(self, cve_id: str) -> List[PoCReference]:
        """
        Return deduplicated, ranked PoC references.
        Sources: Trickest → GitHub API → Vulhub check.
        """
        cache_key = f"poc:v2:{cve_id}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return [PoCReference(**p) for p in cached]

        # Run all sources
        trickest = await self._fetch_trickest(cve_id)
        github = await self._fetch_github_api(cve_id)
        vulhub = await self._check_vulhub(cve_id)

        # Merge — GitHub API first (has star data), then trickest, then vulhub
        seen: set[str] = set()
        merged: List[PoCReference] = []
        for poc in github + trickest + vulhub:
            url = _clean_github_url(poc.url)
            if not _is_valid_poc_url(url):
                continue
            if url not in seen:
                seen.add(url)
                poc.url = url
                merged.append(poc)

        # Sort: starred repos first, then by source priority
        merged.sort(key=lambda p: (-(p.stars or 0), p.source))

        await self._cache.set(cache_key, [p.model_dump() for p in merged])
        return merged

    # ── Trickest mirror ────────────────────────────────────────────────

    async def _fetch_trickest(self, cve_id: str) -> List[PoCReference]:
        """
        Fetch the trickest CVE markdown page and extract all GitHub URLs.
        URL format: https://raw.githubusercontent.com/trickest/cve/main/YYYY/CVE-YYYY-NNNNN.md
        """
        year = cve_id.split("-")[1]
        url = f"{self._cfg.trickest_base_url}/{year}/{cve_id}.md"
        log.debug("Fetching trickest: %s", url)
        text = await self._http.get_text(url)
        if not text:
            return []

        raw_urls = _GH_URL_RE.findall(text)
        seen: set[str] = set()
        results: List[PoCReference] = []
        for raw in raw_urls:
            clean = _clean_github_url(raw)
            if clean not in seen and _is_valid_poc_url(clean):
                seen.add(clean)
                results.append(PoCReference(url=clean, source="trickest"))

        log.debug("Trickest found %d PoCs for %s", len(results), cve_id)
        return results[:15]

    # ── GitHub Search API ──────────────────────────────────────────────

    async def _fetch_github_api(self, cve_id: str) -> List[PoCReference]:
        """
        Search GitHub repositories for PoCs.
        Requires a GitHub token (recommended — unauthenticated rate limit is tiny).
        Filters out forks. Ranks by star count.
        """
        if not self._cfg.github_token:
            log.debug("No GitHub token — skipping GitHub API search for %s", cve_id)
            return []

        headers = {
            "Authorization": f"Bearer {self._cfg.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        data = await self._http.get(
            _GITHUB_SEARCH_URL,
            params={
                "q": f"{cve_id} in:name,description,readme",
                "sort": "stars",
                "order": "desc",
                "per_page": 15,
            },
            extra_headers=headers,
        )
        if not data:
            return []

        results: List[PoCReference] = []
        for item in data.get("items", []):
            if item.get("fork"):
                continue
            results.append(
                PoCReference(
                    url=item.get("html_url", ""),
                    stars=item.get("stargazers_count"),
                    is_fork=False,
                    source="github_api",
                    description=item.get("description"),
                )
            )

        log.debug("GitHub API found %d PoCs for %s", len(results), cve_id)
        return results

    # ── Vulhub ────────────────────────────────────────────────────────

    async def _check_vulhub(self, cve_id: str) -> List[PoCReference]:
        """
        Check if Vulhub has a ready-to-use Docker PoC environment.
        Vulhub path: vulhub/vulhub/tree/master/{PRODUCT}/{CVE-ID}
        We probe the raw README to confirm existence.
        """
        # Vulhub uses product folders — we need to guess the product.
        # Strategy: search GitHub for the CVE in the vulhub repo.
        if not self._cfg.github_token:
            return []

        headers = {
            "Authorization": f"Bearer {self._cfg.github_token}",
            "Accept": "application/vnd.github+json",
        }
        data = await self._http.get(
            _GITHUB_CODE_SEARCH_URL,
            params={
                "q": f"{cve_id} repo:vulhub/vulhub",
                "per_page": 3,
            },
            extra_headers=headers,
        )
        if not data or not data.get("items"):
            return []

        results: List[PoCReference] = []
        for item in data.get("items", [])[:3]:
            path = item.get("path", "")
            # path looks like: "apache/log4j/CVE-2021-44228/README.md"
            parts = path.split("/")
            if len(parts) >= 3:
                folder = "/".join(parts[:-1])  # strip README.md
                vuln_url = f"{self._cfg.vulhub_base}/{folder}"
                results.append(
                    PoCReference(
                        url=vuln_url,
                        source="vulhub",
                        description="Docker-based PoC environment (Vulhub)",
                    )
                )

        return results
