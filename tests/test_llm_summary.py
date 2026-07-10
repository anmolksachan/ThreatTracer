"""Tests for the local-LLM summariser and its deterministic fallback."""

import pytest

from threattracer.core.llm_summary import (
    LLMSummariser,
    _summary_to_prompt,
    heuristic_summary,
)
from threattracer.core.triage import summarise_records
from threattracer.utils.config import AppConfig
from threattracer.utils.models import CVERecord, CVSSMetrics, MSFModule, Severity


def _summary_with_findings():
    recs = [
        CVERecord(
            cve_id="CVE-2021-44228",
            cvss=CVSSMetrics(base_score=10.0, severity=Severity.CRITICAL),
            epss_score=0.97, in_kev=True, kev_ransomware_use="Known",
            msf_modules=[MSFModule(name="m", fullname="exploit/x", description="d", module_type="exploit")],
        ),
    ]
    return summarise_records(recs, target="apache log4j 2.14.1", scan_type="component")


def test_heuristic_summary_nonempty():
    text = heuristic_summary(_summary_with_findings())
    assert "CVE-2021-44228" in text
    assert "posture" in text.lower()


def test_heuristic_summary_no_cves():
    empty = summarise_records([], target="example.com")
    text = heuristic_summary(empty)
    assert "No CVEs" in text


def test_prompt_contains_findings_and_guardrails():
    prompt = _summary_to_prompt(_summary_with_findings(), max_items=25)
    assert "CVE-2021-44228" in prompt
    assert "priority" in prompt.lower()


def test_provider_off_uses_heuristic():
    cfg = AppConfig(llm_provider="off")
    import asyncio
    result = asyncio.run(LLMSummariser(cfg).summarise(_summary_with_findings()))
    assert result.engine == "heuristic"
    assert not result.degraded          # 'off' is a deliberate choice, not a failure
    assert result.text


@pytest.mark.asyncio
async def test_unreachable_llm_degrades_gracefully():
    # Point at a port nothing is listening on; must fall back, never raise.
    cfg = AppConfig(
        llm_provider="ollama",
        llm_ollama_url="http://127.0.0.1:1",   # unreachable
        llm_timeout=2,
    )
    result = await LLMSummariser(cfg).summarise(_summary_with_findings())
    assert result.engine == "heuristic"
    assert result.degraded is True
    assert result.note                          # explains why
    assert result.text                          # still produced a briefing


@pytest.mark.asyncio
async def test_probe_never_raises():
    cfg = AppConfig(llm_ollama_url="http://127.0.0.1:1",
                    llm_openai_url="http://127.0.0.1:1", llm_timeout=2)
    status = await LLMSummariser(cfg).probe()
    assert status["ollama"] is False
    assert status["openai"] is False
