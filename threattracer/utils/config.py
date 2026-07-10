"""
threattracer.utils.config
~~~~~~~~~~~~~~~~~~~~~~~~~
Centralised configuration.

Precedence for secrets/settings (highest first):
    1. explicit CLI argument
    2. environment variable
    3. persisted ~/.threattracer/config.json
    4. built-in default
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

log = logging.getLogger(__name__)

_CONFIG_DIR = Path.home() / ".threattracer"
_CONFIG_FILE = _CONFIG_DIR / "config.json"
_CACHE_DB = _CONFIG_DIR / "cache.db"


class AppConfig(BaseModel):
    """Immutable runtime configuration."""

    model_config = ConfigDict(frozen=True)

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

    # Trickest PoC mirror
    trickest_base_url: str = "https://raw.githubusercontent.com/trickest/cve/main"

    # CISA KEV
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Nuclei templates (GitHub Contents API + raw/browse bases)
    nuclei_contents_api: str = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves"
    nuclei_raw_base: str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves"
    nuclei_browse_base: str = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves"
    # If True, fetch each matched template's raw YAML to extract name/severity/tags.
    # Costs extra HTTP calls; disable for speed.
    nuclei_fetch_meta: bool = True
    nuclei_meta_concurrency: int = 4

    # Vulhub PoC environments
    vulhub_base: str = "https://github.com/vulhub/vulhub/tree/master"

    # Metasploit module index
    msf_index_url: str = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

    # PacketStorm search
    packetstorm_search: str = "https://packetstormsecurity.com/search/?q={cve_id}&s=files"

    # Display
    default_limit: int = 50
    user_agent: str = "ThreatTracer/5.0 (security-research)"

    # Asset scanning
    wappalyzer_timeout: int = 15
    asset_max_concurrent: int = 5

    # ── Local LLM summariser (optional) ────────────────────────────────
    # provider: "auto" | "ollama" | "openai" | "off"
    #   auto   -> probe Ollama, then an OpenAI-compatible endpoint, else heuristic
    #   ollama -> talk to an Ollama daemon (http://localhost:11434 by default)
    #   openai -> talk to any OpenAI-compatible /v1/chat/completions server
    #             (llama.cpp server, LM Studio, vLLM, text-generation-webui, ...)
    #   off    -> never call an LLM; always use the deterministic heuristic
    llm_provider: str = "auto"
    llm_ollama_url: str = "http://localhost:11434"
    llm_openai_url: str = "http://localhost:8080"          # llama.cpp / LM Studio default
    llm_openai_key: Optional[str] = None                   # usually not needed for local
    llm_model: str = "llama3.2"                            # sensible small default
    llm_timeout: int = 90
    llm_max_cves_in_prompt: int = 25

    def with_overrides(self, **changes) -> "AppConfig":
        """Return a copy with selected fields overridden (frozen-model friendly)."""
        return self.model_copy(update={k: v for k, v in changes.items() if v is not None})


def _read_persisted() -> dict:
    if not _CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(_CONFIG_FILE.read_text())
    except Exception as exc:  # corrupt file, permission error, etc.
        log.warning("Could not read config file %s: %s", _CONFIG_FILE, exc)
        return {}


def load_config(
    nvd_api_key: Optional[str] = None,
    github_token: Optional[str] = None,
    **overrides,
) -> AppConfig:
    """Build an AppConfig honouring CLI > env > persisted > default precedence."""
    persisted = _read_persisted()

    env_nvd = os.getenv("THREATTRACER_NVD_KEY") or os.getenv("NVD_API_KEY")
    env_gh = os.getenv("THREATTRACER_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN")

    resolved_nvd = nvd_api_key or env_nvd or persisted.get("nvd_api_key")
    resolved_gh = github_token or env_gh or persisted.get("github_token")

    # LLM settings: env > persisted > default
    llm_fields = {
        "llm_provider": os.getenv("THREATTRACER_LLM_PROVIDER") or persisted.get("llm_provider"),
        "llm_ollama_url": os.getenv("THREATTRACER_LLM_OLLAMA_URL") or persisted.get("llm_ollama_url"),
        "llm_openai_url": os.getenv("THREATTRACER_LLM_OPENAI_URL") or persisted.get("llm_openai_url"),
        "llm_openai_key": os.getenv("THREATTRACER_LLM_OPENAI_KEY") or persisted.get("llm_openai_key"),
        "llm_model": os.getenv("THREATTRACER_LLM_MODEL") or persisted.get("llm_model"),
    }
    llm_fields = {k: v for k, v in llm_fields.items() if v is not None}
    llm_fields.update({k: v for k, v in overrides.items() if v is not None})

    try:
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.warning("Could not create config dir %s: %s", _CONFIG_DIR, exc)

    return AppConfig(
        nvd_api_key=resolved_nvd,
        github_token=resolved_gh,
        **llm_fields,
    )


def persist_api_key(key: str, key_type: str = "nvd") -> None:
    """Persist a single secret/setting into config.json."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = _read_persisted()

    field_map = {
        "nvd": "nvd_api_key",
        "github": "github_token",
    }
    field = field_map.get(key_type, key_type)  # allow arbitrary llm_* keys too
    data[field] = key
    tmp = _CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(_CONFIG_FILE)  # atomic on POSIX
