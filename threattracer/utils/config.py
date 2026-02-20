"""
threattracer.utils.config
~~~~~~~~~~~~~~~~~~~~~~~~~
Centralised configuration.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

_CONFIG_DIR = Path.home() / ".threattracer"
_CONFIG_FILE = _CONFIG_DIR / "config.json"
_CACHE_DB = _CONFIG_DIR / "cache.db"


class AppConfig(BaseModel):
    """Immutable runtime configuration."""

    nvd_api_key: Optional[str] = Field(default=None)
    github_token: Optional[str] = Field(default=None)

    # Network
    request_timeout: int = Field(default=30)
    max_retries: int = Field(default=3)
    retry_base_delay: float = Field(default=1.0)

    # Cache
    cache_db_path: Path = Field(default=_CACHE_DB)
    cache_ttl_seconds: int = Field(default=3600 * 6)

    # NVD
    nvd_cve_endpoint: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_cpe_endpoint: str = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

    # Exploit-DB
    exploitdb_csv_url: str = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )

    # EPSS
    epss_base_url: str = "https://api.first.org/data/v1/epss"

    # Trickest PoC mirror  (FIXED: use main not refs/heads/main)
    trickest_base_url: str = "https://raw.githubusercontent.com/trickest/cve/main"

    # CISA KEV
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Nuclei templates index
    nuclei_index_url: str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/.index"
    nuclei_template_base: str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves"
    nuclei_browse_base: str = "https://github.com/projectdiscovery/nuclei-templates/blob/main/cves"

    # Vulhub PoC environments
    vulhub_base: str = "https://github.com/vulhub/vulhub/tree/master"

    # Metasploit module index
    msf_index_url: str = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

    # PacketStorm search
    packetstorm_search: str = "https://packetstormsecurity.com/search/?q={cve_id}&s=files"

    # Display
    default_limit: int = 50
    user_agent: str = "ThreatTracer/4.0 (security-research)"

    # Asset scanning
    wappalyzer_timeout: int = 15
    asset_max_concurrent: int = 5

    class Config:
        frozen = True


def load_config(
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
) -> AppConfig:
    import json

    persisted: dict = {}
    if _CONFIG_FILE.exists():
        try:
            persisted = json.loads(_CONFIG_FILE.read_text())
        except Exception:
            pass

    env_nvd = os.getenv("THREATTRACER_NVD_KEY") or os.getenv("NVD_API_KEY")
    env_gh = os.getenv("THREATTRACER_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN")

    resolved_nvd = nvd_api_key or env_nvd or persisted.get("nvd_api_key")
    resolved_gh = github_token or env_gh or persisted.get("github_token")

    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return AppConfig(nvd_api_key=resolved_nvd, github_token=resolved_gh)


def persist_api_key(key: str, key_type: str = "nvd") -> None:
    import json

    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if _CONFIG_FILE.exists():
        try:
            data = json.loads(_CONFIG_FILE.read_text())
        except Exception:
            pass

    field = "nvd_api_key" if key_type == "nvd" else "github_token"
    data[field] = key
    _CONFIG_FILE.write_text(json.dumps(data, indent=2))
