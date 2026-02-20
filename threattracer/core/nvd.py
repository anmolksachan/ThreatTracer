"""
threattracer.core.nvd
~~~~~~~~~~~~~~~~~~~~~
NVD REST API v2 client.

Responsibilities:
  - Fetch CVE details by CVE-ID or CPE string
  - Parse CVSS v3 (fallback v2) metrics
  - Fetch EPSS scores from api.first.org
  - Cache all remote responses
"""

from __future__ import annotations

import logging
from typing import List, Optional

from threattracer.utils.cache import ResponseCache
from threattracer.utils.config import AppConfig
from threattracer.utils.http_client import AsyncHTTPClient
from threattracer.utils.models import CVERecord, CVSSMetrics, Severity, cvss_to_severity

log = logging.getLogger(__name__)


def _nvd_headers(config: AppConfig) -> dict:
    h = {}
    if config.nvd_api_key:
        h["apiKey"] = config.nvd_api_key
    return h


def _parse_cvss(cve_dict: dict) -> Optional[CVSSMetrics]:
    """Extract CVSS v3 (preferred) or v2 metrics from raw NVD CVE dict."""
    metrics = cve_dict.get("metrics", {})

    # Try CVSS v3.1 → v3.0 → v2
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            primary = next(
                (e for e in entries if e.get("type") == "Primary"), entries[0]
            )
            cvss_data = primary.get("cvssData", {})
            score = cvss_data.get("baseScore")
            return CVSSMetrics(
                version="3.x",
                base_score=score,
                severity=cvss_to_severity(score),
                attack_vector=cvss_data.get("attackVector"),
                attack_complexity=cvss_data.get("attackComplexity"),
                privileges_required=cvss_data.get("privilegesRequired"),
                user_interaction=cvss_data.get("userInteraction"),
                confidentiality_impact=cvss_data.get("confidentialityImpact"),
                integrity_impact=cvss_data.get("integrityImpact"),
                availability_impact=cvss_data.get("availabilityImpact"),
            )

    entries_v2 = metrics.get("cvssMetricV2", [])
    if entries_v2:
        primary = next(
            (e for e in entries_v2 if e.get("type") == "Primary"), entries_v2[0]
        )
        cvss_data = primary.get("cvssData", {})
        score = cvss_data.get("baseScore")
        sev_str = primary.get("baseSeverity", "")
        try:
            sev = Severity(sev_str.upper())
        except ValueError:
            sev = cvss_to_severity(score)
        return CVSSMetrics(version="2.0", base_score=score, severity=sev)

    return None


def _parse_vulnerabilities(raw: dict) -> List[CVERecord]:
    records: List[CVERecord] = []
    for item in raw.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id: str = cve.get("id", "UNKNOWN")

        # Description (English preferred)
        descs = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descs if d.get("lang") == "en"),
            descs[0]["value"] if descs else "N/A",
        )

        # Weaknesses (CWEs)
        weaknesses: List[str] = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value") not in weaknesses:
                    weaknesses.append(d["value"])

        records.append(
            CVERecord(
                cve_id=cve_id,
                description=description,
                weaknesses=weaknesses,
                nvd_link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published=cve.get("published"),
                last_modified=cve.get("lastModified"),
                cvss=_parse_cvss(cve),
            )
        )
    return records


class NVDClient:
    """Async NVD API v2 client."""

    def __init__(
        self,
        config: AppConfig,
        http: AsyncHTTPClient,
        cache: ResponseCache,
    ) -> None:
        self._cfg = config
        self._http = http
        self._cache = cache

    async def fetch_by_cve_id(self, cve_id: str) -> List[CVERecord]:
        """Fetch one CVE record by ID."""
        cache_key = f"nvd:cve:{cve_id}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            log.debug("Cache hit: %s", cache_key)
            return [CVERecord(**r) for r in cached]

        data = await self._http.get(
            self._cfg.nvd_cve_endpoint,
            params={"cveId": cve_id},
            extra_headers=_nvd_headers(self._cfg),
        )
        if data is None:
            return []

        records = _parse_vulnerabilities(data)
        await self._cache.set(cache_key, [r.model_dump() for r in records])
        return records

    async def fetch_by_cpe(
        self, cpe_string: str, results_per_page: int = 500
    ) -> List[CVERecord]:
        """Fetch all CVEs matching a CPE name."""
        cache_key = f"nvd:cpe:{cpe_string}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            log.debug("Cache hit: %s", cache_key)
            return [CVERecord(**r) for r in cached]

        data = await self._http.get(
            self._cfg.nvd_cve_endpoint,
            params={
                "cpeName": cpe_string,
                "resultsPerPage": results_per_page,
            },
            extra_headers=_nvd_headers(self._cfg),
        )
        if data is None:
            return []

        records = _parse_vulnerabilities(data)
        await self._cache.set(cache_key, [r.model_dump() for r in records])
        return records

    async def enrich_with_epss(self, records: List[CVERecord]) -> None:
        """
        Fetch EPSS scores for a list of CVE records (mutates in place).
        Batches up to 100 CVE-IDs per request.
        """
        if not records:
            return
        ids = [r.cve_id for r in records]

        # Split into batches of 100
        for batch_start in range(0, len(ids), 100):
            batch = ids[batch_start : batch_start + 100]
            cache_key = f"epss:{','.join(batch)}"
            cached = await self._cache.get(cache_key)

            if cached is not None:
                epss_map: dict = cached
            else:
                data = await self._http.get(
                    self._cfg.epss_base_url,
                    params={"cve": ",".join(batch)},
                )
                if data is None:
                    continue
                epss_map = {
                    entry["cve"]: entry
                    for entry in data.get("data", [])
                }
                await self._cache.set(cache_key, epss_map)

            for record in records[batch_start : batch_start + 100]:
                entry = epss_map.get(record.cve_id)
                if entry:
                    try:
                        record.epss_score = float(entry.get("epss", 0))
                        record.epss_percentile = float(entry.get("percentile", 0))
                    except (TypeError, ValueError):
                        pass
