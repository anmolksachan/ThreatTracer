"""
threattracer.utils.validate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Small input-validation helpers shared across core modules.

Guarding CVE-ID parsing centrally means a malformed identifier (e.g. ``CVE-``,
``cve2021``, ``''``) degrades gracefully to "no results" instead of raising an
IndexError deep inside a network client.
"""

from __future__ import annotations

import re

_CVE_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$", re.IGNORECASE)


def is_valid_cve(cve_id: str) -> bool:
    """True if ``cve_id`` matches the canonical CVE-YYYY-NNNN[..] form."""
    return bool(cve_id) and bool(_CVE_RE.match(cve_id.strip()))


def cve_year(cve_id: str) -> str | None:
    """Return the 4-digit year from a CVE ID, or None if it is malformed."""
    m = _CVE_RE.match((cve_id or "").strip())
    return m.group(1) if m else None


def normalise_cve(cve_id: str) -> str:
    """Upper-case and trim a CVE ID (does not validate)."""
    return (cve_id or "").strip().upper()
