"""
threattracer.utils.models
~~~~~~~~~~~~~~~~~~~~~~~~~
Shared Pydantic data models.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.NONE: 4,
    Severity.UNKNOWN: 5,
}


def cvss_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE


class ExploitEntry(BaseModel):
    id: str
    description: str
    link: str
    exploit_type: Optional[str] = None
    platform: Optional[str] = None


class PoCReference(BaseModel):
    url: str
    stars: Optional[int] = None
    is_fork: bool = False
    source: str = "trickest"
    description: Optional[str] = None   # NEW: repo description or context


class NucleiTemplate(BaseModel):
    """A Nuclei template that can directly test this CVE."""
    template_id: str
    name: str
    severity: str
    url: str                             # raw github URL to the template
    tags: List[str] = Field(default_factory=list)


class MSFModule(BaseModel):
    """A Metasploit module for this CVE."""
    name: str
    fullname: str
    description: str
    module_type: str   # exploit / auxiliary / post


class CVSSMetrics(BaseModel):
    version: str = "3.x"
    base_score: Optional[float] = None
    severity: Severity = Severity.UNKNOWN
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None


class CVERecord(BaseModel):
    cve_id: str
    description: str = "N/A"
    weaknesses: List[str] = Field(default_factory=list)
    nvd_link: str = ""
    published: Optional[str] = None
    last_modified: Optional[str] = None
    cvss: Optional[CVSSMetrics] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    exploits: List[ExploitEntry] = Field(default_factory=list)
    pocs: List[PoCReference] = Field(default_factory=list)
    nuclei_templates: List[NucleiTemplate] = Field(default_factory=list)   # NEW
    msf_modules: List[MSFModule] = Field(default_factory=list)             # NEW
    in_kev: bool = False                                                    # NEW: CISA KEV
    kev_date_added: Optional[str] = None                                   # NEW
    kev_ransomware_use: Optional[str] = None                               # NEW
    vulhub_url: Optional[str] = None                                       # NEW

    @property
    def severity(self) -> Severity:
        if self.cvss:
            return self.cvss.severity
        return Severity.UNKNOWN

    @property
    def cvss_score(self) -> Optional[float]:
        return self.cvss.base_score if self.cvss else None

    @property
    def has_exploit(self) -> bool:
        return bool(self.exploits or self.pocs or self.msf_modules)

    @property
    def weaponised(self) -> bool:
        """True if this CVE has a ready-to-fire weapon (MSF module or KEV)."""
        return bool(self.msf_modules or self.in_kev)


class CPEMatch(BaseModel):
    cpe_name: str
    title: Optional[str] = None
    match_score: float = 0.0


# ── Asset scanning models ──────────────────────────────────────────────────

class DetectedTech(BaseModel):
    """A technology fingerprinted on an asset."""
    name: str
    version: Optional[str] = None
    categories: List[str] = Field(default_factory=list)
    confidence: int = 100   # 0-100


class AssetScanResult(BaseModel):
    """Result of scanning a single URL target."""
    url: str
    final_url: str = ""                  # after redirects
    status_code: Optional[int] = None
    server: Optional[str] = None
    technologies: List[DetectedTech] = Field(default_factory=list)
    cve_results: List["ComponentCVEResult"] = Field(default_factory=list)
    error: Optional[str] = None

    @property
    def total_cves(self) -> int:
        return sum(len(r.records) for r in self.cve_results)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for r in self.cve_results
            for rec in r.records
            if rec.severity == Severity.CRITICAL
        )

    @property
    def weaponised_count(self) -> int:
        return sum(
            1 for r in self.cve_results
            for rec in r.records
            if rec.weaponised
        )


class ComponentCVEResult(BaseModel):
    """CVEs for one detected technology component."""
    tech: DetectedTech
    cpe_matches: List[CPEMatch] = Field(default_factory=list)
    records: List[CVERecord] = Field(default_factory=list)


AssetScanResult.model_rebuild()
