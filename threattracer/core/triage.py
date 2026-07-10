"""
threattracer.core.triage
~~~~~~~~~~~~~~~~~~~~~~~~~
Deterministic risk-prioritisation engine.

This module contains *no* network calls and *no* exploitation logic.  It takes
the enriched CVE records a scan already produced and answers one operator
question:  **"Given everything we found, what should I look at first?"**

The priority score (0-100) blends four independent, publicly-sourced signals:

    * CISA KEV membership        — confirmed real-world exploitation (strongest)
    * EPSS                       — FIRST.org probability of exploitation
    * CVSS base score            — theoretical severity
    * public tooling maturity    — is there a PoC / Exploit-DB entry / MSF module?

It is decision support for defenders and authorised testers deciding patch and
verification order — not a promise that anything is exploitable in a given
environment.
"""

from __future__ import annotations


from typing import Iterable, List, Optional, Tuple

from threattracer.utils.models import (
    CVERecord,
    ScanSummary,
    Severity,
    TriageItem,
)

# Relative weights — sum is normalised, so absolute magnitudes only matter
# relative to each other.
_W_KEV = 40.0        # binary: in the KEV catalog or not
_W_EPSS = 25.0       # scaled by epss (0-1)
_W_CVSS = 20.0       # scaled by cvss/10
_W_MATURITY = 15.0   # scaled by exploit-tooling maturity (0-1)

_MATURITY_WEIGHT = {
    "none": 0.0,
    "poc": 0.45,
    "edb": 0.75,
    "weaponised": 1.0,
}


def _exploit_maturity(record: CVERecord) -> str:
    """Classify how 'ready' public exploitation tooling is for this CVE."""
    if record.msf_modules or record.in_kev:
        return "weaponised"
    if record.exploits:            # Exploit-DB entry = working standalone exploit
        return "edb"
    if record.nuclei_templates:    # a detection/verification template exists
        return "edb"
    if record.pocs:
        return "poc"
    return "none"


def score_record(record: CVERecord) -> Tuple[float, List[str], str]:
    """Return (priority_score, signals, human_reason) for one CVE record."""
    signals: List[str] = []

    kev_component = _W_KEV if record.in_kev else 0.0
    if record.in_kev:
        signals.append("CISA KEV")
        if (record.kev_ransomware_use or "").lower() == "known":
            signals.append("ransomware")

    epss = record.epss_score or 0.0
    epss_component = _W_EPSS * max(0.0, min(epss, 1.0))
    if epss >= 0.5:
        signals.append(f"EPSS {epss * 100:.0f}%")

    cvss = record.cvss_score or 0.0
    cvss_component = _W_CVSS * max(0.0, min(cvss, 10.0)) / 10.0
    if record.severity in (Severity.CRITICAL, Severity.HIGH):
        signals.append(record.severity.value.title())

    maturity = _exploit_maturity(record)
    maturity_component = _W_MATURITY * _MATURITY_WEIGHT.get(maturity, 0.0)
    if maturity == "weaponised" and "CISA KEV" not in signals:
        signals.append("MSF module")
    elif maturity == "edb":
        signals.append("public exploit")
    elif maturity == "poc":
        signals.append("PoC available")

    score = kev_component + epss_component + cvss_component + maturity_component
    score = round(min(score, 100.0), 1)

    reason = _build_reason(record, maturity, epss)
    return score, signals, reason


def _build_reason(record: CVERecord, maturity: str, epss: float) -> str:
    bits: List[str] = []
    if record.in_kev:
        ransom = (record.kev_ransomware_use or "").lower() == "known"
        bits.append(
            "actively exploited in the wild (CISA KEV"
            + (", ransomware-linked)" if ransom else ")")
        )
    if maturity == "weaponised" and not record.in_kev:
        bits.append("a ready-to-use Metasploit module exists")
    elif maturity == "edb":
        bits.append("a public exploit or verification template exists")
    elif maturity == "poc":
        bits.append("proof-of-concept code is published")
    if epss >= 0.5:
        bits.append(f"EPSS predicts a {epss * 100:.0f}% chance of exploitation")
    if record.severity in (Severity.CRITICAL, Severity.HIGH) and not bits:
        bits.append(f"{record.severity.value.lower()} CVSS severity")
    if not bits:
        bits.append("no public exploitation signals yet")
    return "; ".join(bits).capitalize()


def build_triage_items(
    records: Iterable[CVERecord],
    component: Optional[str] = None,
) -> List[TriageItem]:
    """Convert enriched CVE records into sorted TriageItems (highest priority first)."""
    items: List[TriageItem] = []
    for r in records:
        score, signals, reason = score_record(r)
        items.append(
            TriageItem(
                cve_id=r.cve_id,
                priority_score=score,
                severity=r.severity,
                cvss_score=r.cvss_score,
                epss_score=r.epss_score,
                in_kev=r.in_kev,
                ransomware=(r.kev_ransomware_use or "").lower() == "known",
                exploit_maturity=_exploit_maturity(r),
                signals=signals,
                reason=reason,
                component=component,
                nvd_link=r.nvd_link,
            )
        )
    items.sort(key=lambda i: i.priority_score, reverse=True)
    return items


def summarise_records(
    records: List[CVERecord],
    target: str = "",
    scan_type: str = "component",
    top_n: int = 10,
    component_map: Optional[dict] = None,
) -> ScanSummary:
    """
    Build a ScanSummary from a flat list of CVERecords.

    ``component_map`` optionally maps ``cve_id -> component_name`` so asset
    scans can attribute each finding to the technology that surfaced it.
    """
    component_map = component_map or {}

    all_items: List[TriageItem] = []
    for r in records:
        score, signals, reason = score_record(r)
        all_items.append(
            TriageItem(
                cve_id=r.cve_id,
                priority_score=score,
                severity=r.severity,
                cvss_score=r.cvss_score,
                epss_score=r.epss_score,
                in_kev=r.in_kev,
                ransomware=(r.kev_ransomware_use or "").lower() == "known",
                exploit_maturity=_exploit_maturity(r),
                signals=signals,
                reason=reason,
                component=component_map.get(r.cve_id),
                nvd_link=r.nvd_link,
            )
        )
    all_items.sort(key=lambda i: i.priority_score, reverse=True)

    return _build_summary(records, all_items, target, scan_type, top_n)


def summarise_asset(asset_result, top_n: int = 10) -> ScanSummary:
    """
    Build one ScanSummary from an AssetScanResult, attributing each CVE to the
    technology (component) that surfaced it.
    """
    records = []
    component_map: dict = {}
    for cr in asset_result.cve_results:
        label = f"{cr.tech.name} {cr.tech.version or ''}".strip()
        for rec in cr.records:
            records.append(rec)
            component_map.setdefault(rec.cve_id, label)

    return summarise_records(
        records,
        target=asset_result.final_url or asset_result.url,
        scan_type="asset",
        top_n=top_n,
        component_map=component_map,
    )


def _build_summary(records, all_items, target, scan_type, top_n) -> ScanSummary:
    def _sev_count(sev: Severity) -> int:
        return sum(1 for r in records if r.severity == sev)

    return ScanSummary(
        target=target,
        scan_type=scan_type,
        total_cves=len(records),
        critical=_sev_count(Severity.CRITICAL),
        high=_sev_count(Severity.HIGH),
        medium=_sev_count(Severity.MEDIUM),
        low=_sev_count(Severity.LOW),
        in_kev=sum(1 for r in records if r.in_kev),
        ransomware_linked=sum(
            1 for r in records if (r.kev_ransomware_use or "").lower() == "known"
        ),
        with_edb=sum(1 for r in records if r.exploits),
        with_poc=sum(1 for r in records if r.pocs),
        with_nuclei=sum(1 for r in records if r.nuclei_templates),
        with_msf=sum(1 for r in records if r.msf_modules),
        weaponised=sum(1 for r in records if r.weaponised),
        top_findings=all_items[:top_n],
    )
