"""Tests for CVE-ID validation helpers."""

from threattracer.utils.validate import cve_year, is_valid_cve, normalise_cve


def test_valid_cves():
    assert is_valid_cve("CVE-2021-44228")
    assert is_valid_cve("cve-2021-44228")          # case-insensitive
    assert is_valid_cve("CVE-2023-1234567")        # long sequence number


def test_invalid_cves():
    assert not is_valid_cve("")
    assert not is_valid_cve("NOTACVE")
    assert not is_valid_cve("CVE-")
    assert not is_valid_cve("CVE-21-44228")        # 2-digit year
    assert not is_valid_cve("2021-44228")          # missing prefix
    assert not is_valid_cve("CVE-2021-44")         # too-short sequence


def test_cve_year():
    assert cve_year("CVE-2021-44228") == "2021"
    assert cve_year("bad") is None


def test_normalise():
    assert normalise_cve("  cve-2021-44228 ") == "CVE-2021-44228"
