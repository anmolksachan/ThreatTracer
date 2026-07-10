"""Tests for the deterministic triage/prioritisation engine."""

from threattracer.core.triage import (
    build_triage_items,
    score_record,
    summarise_records,
)
from threattracer.utils.models import (
    CVERecord,
    CVSSMetrics,
    ExploitEntry,
    MSFModule,
    NucleiTemplate,
    PoCReference,
    Severity,
)


def _rec(cid, score, sev, **kw):
    return CVERecord(
        cve_id=cid,
        cvss=CVSSMetrics(base_score=score, severity=sev),
        **kw,
    )


def test_kev_ranks_highest():
    kev = _rec("CVE-2021-44228", 10.0, Severity.CRITICAL, in_kev=True, epss_score=0.9)
    plain = _rec("CVE-2020-0001", 9.8, Severity.CRITICAL, epss_score=0.9)
    s_kev, _, _ = score_record(kev)
    s_plain, _, _ = score_record(plain)
    assert s_kev > s_plain


def test_score_bounds():
    everything = _rec(
        "CVE-2021-44228", 10.0, Severity.CRITICAL,
        in_kev=True, kev_ransomware_use="Known", epss_score=1.0,
        msf_modules=[MSFModule(name="m", fullname="exploit/x", description="d", module_type="exploit")],
    )
    score, signals, reason = score_record(everything)
    assert 0.0 <= score <= 100.0
    assert score > 90                       # all signals present → near max
    assert "CISA KEV" in signals
    assert "ransomware" in signals


def test_empty_signals_low_score():
    nothing = _rec("CVE-2022-9999", 0.0, Severity.NONE)
    score, signals, reason = score_record(nothing)
    assert score == 0.0
    assert reason  # always has a human-readable reason


def test_maturity_classification():
    weaponised = _rec("CVE-1", 8.0, Severity.HIGH,
                      msf_modules=[MSFModule(name="m", fullname="x", description="", module_type="exploit")])
    edb = _rec("CVE-2", 8.0, Severity.HIGH,
               exploits=[ExploitEntry(id="1", description="", link="http://x")])
    poc = _rec("CVE-3", 8.0, Severity.HIGH,
               pocs=[PoCReference(url="https://github.com/a/b", source="trickest")])
    none = _rec("CVE-4", 8.0, Severity.HIGH)
    items = build_triage_items([weaponised, edb, poc, none])
    by_id = {i.cve_id: i for i in items}
    assert by_id["CVE-1"].exploit_maturity == "weaponised"
    assert by_id["CVE-2"].exploit_maturity == "edb"
    assert by_id["CVE-3"].exploit_maturity == "poc"
    assert by_id["CVE-4"].exploit_maturity == "none"


def test_nuclei_counts_as_verification_tooling():
    nuc = _rec("CVE-5", 7.0, Severity.HIGH,
               nuclei_templates=[NucleiTemplate(template_id="t", name="n", severity="high", url="u")])
    assert build_triage_items([nuc])[0].exploit_maturity == "edb"


def test_summary_counts_and_sorting():
    recs = [
        _rec("CVE-A", 10.0, Severity.CRITICAL, in_kev=True, kev_ransomware_use="Known", epss_score=0.95),
        _rec("CVE-B", 8.5, Severity.HIGH, epss_score=0.4),
        _rec("CVE-C", 3.0, Severity.LOW),
    ]
    summary = summarise_records(recs, target="apache 2.4", scan_type="component")
    assert summary.total_cves == 3
    assert summary.critical == 1
    assert summary.high == 1
    assert summary.low == 1
    assert summary.in_kev == 1
    assert summary.ransomware_linked == 1
    # top finding is the KEV/ransomware one
    assert summary.top_findings[0].cve_id == "CVE-A"
    # sorted descending
    scores = [i.priority_score for i in summary.top_findings]
    assert scores == sorted(scores, reverse=True)


def test_component_attribution():
    recs = [_rec("CVE-A", 9.0, Severity.CRITICAL)]
    summary = summarise_records(
        recs, component_map={"CVE-A": "nginx 1.18"}
    )
    assert summary.top_findings[0].component == "nginx 1.18"
