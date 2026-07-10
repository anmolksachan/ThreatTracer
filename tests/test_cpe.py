"""
tests.test_cpe
~~~~~~~~~~~~~~
Tests for CPE search, scoring, and vendor normalisation.
"""

from __future__ import annotations

import pytest

from threattracer.core.cpe import _normalise_vendor, _score_cpe, _cpe_title


def test_vendor_normalisation():
    assert _normalise_vendor("Apache Software Foundation") == "apache"
    assert _normalise_vendor("Microsoft") == "microsoft"
    assert _normalise_vendor("Sun Microsystems") == "oracle"
    assert _normalise_vendor("unknown_vendor_xyz") == "unknown_vendor_xyz"


def test_cpe_title_extraction():
    cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    title = _cpe_title(cpe)
    assert "apache" in title.lower()
    assert "log4j" in title.lower()


def test_cpe_score_exact_version():
    cpe = "cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*"
    score = _score_cpe(cpe, "apache", "2.4.51")
    # Should be high because version matches exactly
    assert score > 50


def test_cpe_score_no_version_match():
    cpe = "cpe:2.3:a:apache:httpd:2.2.0:*:*:*:*:*:*:*"
    score = _score_cpe(cpe, "apache", "2.4.51")
    # Version mismatch should lower score vs exact match
    score_exact = _score_cpe(
        "cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*", "apache", "2.4.51"
    )
    assert score_exact >= score


def test_cpe_score_unrelated_vendor():
    cpe = "cpe:2.3:a:microsoft:iis:10.0:*:*:*:*:*:*:*"
    score = _score_cpe(cpe, "apache", "2.4.51")
    assert score < 60  # Should not score high for unrelated vendor


@pytest.mark.asyncio
async def test_cpe_client_search_cached():
    from unittest.mock import AsyncMock, MagicMock
    from threattracer.core.cpe import CPEClient
    from threattracer.utils.config import AppConfig

    config = AppConfig()

    raw_products = [
        {
            "cpe": {
                "cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                "titles": [{"lang": "en", "title": "Apache Log4j 2.14.1"}],
            }
        }
    ]

    mock_cache = MagicMock()
    mock_cache.get = AsyncMock(return_value=raw_products)
    mock_cache.set = AsyncMock()

    mock_http = MagicMock()

    client = CPEClient(config, mock_http, mock_cache)
    matches = await client.search("apache log4j", "2.14.1", top_n=5)

    assert len(matches) == 1
    assert "log4j" in matches[0].cpe_name.lower()
    mock_http.get.assert_not_called()
