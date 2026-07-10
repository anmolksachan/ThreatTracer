"""Tests that malformed CVE IDs degrade to empty results, not exceptions."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from threattracer.core.github_poc import GitHubPoCClient
from threattracer.core.nuclei_check import NucleiCheckClient
from threattracer.utils.config import AppConfig


def _mocks():
    cfg = AppConfig()
    http = MagicMock()
    http.get = AsyncMock(return_value=None)
    http.get_text = AsyncMock(return_value=None)
    cache = MagicMock()
    cache.get = AsyncMock(return_value=None)
    cache.set = AsyncMock()
    return cfg, http, cache


@pytest.mark.asyncio
async def test_github_poc_rejects_malformed_cve():
    cfg, http, cache = _mocks()
    client = GitHubPoCClient(cfg, http, cache)
    assert await client.find_pocs("NOTACVE") == []
    assert await client.find_pocs("") == []


@pytest.mark.asyncio
async def test_nuclei_rejects_malformed_cve():
    cfg, http, cache = _mocks()
    client = NucleiCheckClient(cfg, http, cache)
    assert await client.find_templates("NOTACVE") == []
    assert await client.find_templates("CVE-99") == []


@pytest.mark.asyncio
async def test_nuclei_handles_403_year_listing():
    # GitHub Contents API returns None (rate-limited) -> empty, no crash.
    cfg, http, cache = _mocks()
    client = NucleiCheckClient(cfg, http, cache)
    assert await client.find_templates("CVE-2021-44228") == []
