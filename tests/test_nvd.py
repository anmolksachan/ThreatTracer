"""
tests.test_nvd
~~~~~~~~~~~~~~
Unit tests for NVD parsing and caching logic.

All network calls are mocked – no real HTTP required.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threattracer.core.nvd import NVDClient, _parse_cvss, _parse_vulnerabilities
from threattracer.utils.models import Severity


# ---------------------------------------------------------------------------
# _parse_cvss
# ---------------------------------------------------------------------------

MOCK_CVE_V31 = {
    "id": "CVE-2021-44228",
    "metrics": {
        "cvssMetricV31": [
            {
                "type": "Primary",
                "cvssData": {
                    "baseScore": 10.0,
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "HIGH",
                    "availabilityImpact": "HIGH",
                },
            }
        ]
    },
}

MOCK_CVE_V2 = {
    "id": "CVE-2001-0001",
    "metrics": {
        "cvssMetricV2": [
            {
                "type": "Primary",
                "baseSeverity": "HIGH",
                "cvssData": {"baseScore": 7.5},
            }
        ]
    },
}

MOCK_CVE_NO_METRICS = {
    "id": "CVE-2023-0001",
    "metrics": {},
}


def test_parse_cvss_v31():
    result = _parse_cvss(MOCK_CVE_V31)
    assert result is not None
    assert result.base_score == 10.0
    assert result.severity == Severity.CRITICAL
    assert result.attack_vector == "NETWORK"
    assert result.privileges_required == "NONE"


def test_parse_cvss_v2_fallback():
    result = _parse_cvss(MOCK_CVE_V2)
    assert result is not None
    assert result.version == "2.0"
    assert result.base_score == 7.5
    assert result.severity == Severity.HIGH


def test_parse_cvss_no_metrics():
    result = _parse_cvss(MOCK_CVE_NO_METRICS)
    assert result is None


# ---------------------------------------------------------------------------
# _parse_vulnerabilities
# ---------------------------------------------------------------------------

MOCK_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:00.000",
                "lastModified": "2023-04-03T00:15:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 RCE vulnerability."},
                    {"lang": "es", "value": "Vulnerabilidad RCE en Apache Log4j2."},
                ],
                "weaknesses": [
                    {"description": [{"value": "CWE-502"}]},
                    {"description": [{"value": "CWE-917"}]},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "type": "Primary",
                            "cvssData": {
                                "baseScore": 10.0,
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                            },
                        }
                    ]
                },
            }
        }
    ]
}


def test_parse_vulnerabilities():
    records = _parse_vulnerabilities(MOCK_NVD_RESPONSE)
    assert len(records) == 1
    r = records[0]
    assert r.cve_id == "CVE-2021-44228"
    assert "RCE" in r.description
    assert "CWE-502" in r.weaknesses
    assert r.cvss is not None
    assert r.cvss.base_score == 10.0
    assert r.severity == Severity.CRITICAL
    assert r.published == "2021-12-10T10:15:00.000"


def test_parse_vulnerabilities_empty():
    records = _parse_vulnerabilities({"vulnerabilities": []})
    assert records == []


# ---------------------------------------------------------------------------
# NVDClient (async, cache miss → HTTP → cache set)
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_config():
    from threattracer.utils.config import AppConfig
    return AppConfig()


@pytest.mark.asyncio
async def test_nvd_client_fetch_by_cve_cache_miss(mock_config):
    mock_http = MagicMock()
    mock_http.get = AsyncMock(return_value=MOCK_NVD_RESPONSE)

    mock_cache = MagicMock()
    mock_cache.get = AsyncMock(return_value=None)
    mock_cache.set = AsyncMock()

    client = NVDClient(mock_config, mock_http, mock_cache)
    records = await client.fetch_by_cve_id("CVE-2021-44228")

    assert len(records) == 1
    assert records[0].cve_id == "CVE-2021-44228"
    mock_http.get.assert_called_once()
    mock_cache.set.assert_called_once()


@pytest.mark.asyncio
async def test_nvd_client_fetch_by_cve_cache_hit(mock_config):
    cached_data = [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Cached description",
            "weaknesses": [],
            "nvd_link": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "published": None,
            "last_modified": None,
            "cvss": None,
            "epss_score": None,
            "epss_percentile": None,
            "exploits": [],
            "pocs": [],
        }
    ]
    mock_http = MagicMock()
    mock_cache = MagicMock()
    mock_cache.get = AsyncMock(return_value=cached_data)
    mock_cache.set = AsyncMock()

    client = NVDClient(mock_config, mock_http, mock_cache)
    records = await client.fetch_by_cve_id("CVE-2021-44228")

    assert len(records) == 1
    assert records[0].description == "Cached description"
    mock_http.get.assert_not_called()
    mock_cache.set.assert_not_called()


@pytest.mark.asyncio
async def test_nvd_client_handles_none_response(mock_config):
    mock_http = MagicMock()
    mock_http.get = AsyncMock(return_value=None)
    mock_cache = MagicMock()
    mock_cache.get = AsyncMock(return_value=None)
    mock_cache.set = AsyncMock()

    client = NVDClient(mock_config, mock_http, mock_cache)
    records = await client.fetch_by_cve_id("CVE-2021-44228")

    assert records == []


# ---------------------------------------------------------------------------
# EPSS enrichment
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_epss_enrichment(mock_config):
    from threattracer.utils.models import CVERecord

    records = [CVERecord(cve_id="CVE-2021-44228", nvd_link="x")]

    mock_http = MagicMock()
    mock_http.get = AsyncMock(
        return_value={
            "data": [{"cve": "CVE-2021-44228", "epss": "0.97534", "percentile": "0.99999"}]
        }
    )
    mock_cache = MagicMock()
    mock_cache.get = AsyncMock(return_value=None)
    mock_cache.set = AsyncMock()

    client = NVDClient(mock_config, mock_http, mock_cache)
    await client.enrich_with_epss(records)

    assert records[0].epss_score == pytest.approx(0.97534)
    assert records[0].epss_percentile == pytest.approx(0.99999)
