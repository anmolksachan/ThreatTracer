"""Tests for the Markdown / HTML report writer."""

from pathlib import Path

from threattracer.cli.report import build_html, build_markdown, write_report
from threattracer.core.triage import summarise_records
from threattracer.utils.models import (
    CVERecord,
    CVSSMetrics,
    LLMSummary,
    MSFModule,
    Severity,
)


def _fixture():
    recs = [
        CVERecord(
            cve_id="CVE-2021-44228",
            description="Log4Shell RCE",
            cvss=CVSSMetrics(base_score=10.0, severity=Severity.CRITICAL),
            epss_score=0.97, in_kev=True, kev_date_added="2021-12-10",
            kev_ransomware_use="Known",
            msf_modules=[MSFModule(name="m", fullname="exploit/multi/http/log4shell",
                                   description="d", module_type="exploit")],
        ),
    ]
    summary = summarise_records(recs, target="apache log4j 2.14.1")
    llm = LLMSummary(text="Risk is HIGH; patch Log4Shell first.", engine="heuristic")
    return summary, recs, llm


def test_markdown_contains_key_sections():
    summary, recs, llm = _fixture()
    md = build_markdown(summary, recs, llm)
    assert "# ThreatTracer Report" in md
    assert "Executive Summary" in md
    assert "CVE-2021-44228" in md
    assert "At a Glance" in md


def test_html_is_wellformed_and_escaped():
    summary, recs, llm = _fixture()
    html = build_html(summary, recs, llm)
    assert html.startswith("<!doctype html>")
    assert "CVE-2021-44228" in html
    assert "</html>" in html


def test_write_report_infers_format(tmp_path: Path):
    summary, recs, llm = _fixture()
    md_path = write_report(tmp_path / "r.md", summary, recs, llm)
    html_path = write_report(tmp_path / "r.html", summary, recs, llm)
    assert md_path.read_text().startswith("# ThreatTracer")
    assert html_path.read_text().startswith("<!doctype html>")


def test_write_report_coerces_unknown_extension(tmp_path: Path):
    summary, recs, llm = _fixture()
    out = write_report(tmp_path / "r.txt", summary, recs, llm)
    assert out.suffix == ".md"      # coerced to markdown
