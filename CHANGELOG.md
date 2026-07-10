## 5.0.1

### Changed
- Lowered `requires-python` to `>=3.9` (was `>=3.10`). The codebase uses
  `from __future__ import annotations` throughout and `typing.List/Optional`
  in models, with no `match`/`case`, `zip(strict=)`, or PEP 604 (`X | Y`) unions
  in evaluated positions, so it runs on 3.9 (e.g. macOS system Python).
  **3.10+ is still recommended** and is what the test suite is run against.

# Changelog

## 5.0.0

### Added
- **Risk-ranked triage engine** (`core/triage.py`) — every scan now produces a
  deterministic 0-100 priority score per CVE, blending CISA KEV membership,
  EPSS probability, CVSS severity, and public exploit-tooling maturity. Shown
  with `--summarize` as a "Prioritised Findings" table.
- **Optional local-LLM briefing** (`core/llm_summary.py`) — `--summarize`
  produces a plain-language triage briefing. Talks to a *local* Ollama or any
  OpenAI-compatible server (llama.cpp, LM Studio, vLLM). No data leaves the
  machine, no cloud key required. Falls back to a deterministic heuristic
  briefing whenever no model is reachable — a scan never fails because of the LLM.
- **Report writer** (`cli/report.py`) — `--report out.md` / `--report out.html`
  writes a self-contained report (the HTML prints cleanly to PDF).
- **`doctor` command** — checks API keys, network reachability (NVD/EPSS/KEV/GitHub),
  cache location, and local-LLM availability in one shot.
- `config` now stores LLM settings (`--llm-provider`, `--llm-model`,
  `--llm-ollama-url`, `--llm-openai-url`) and has `--show`.
- CVE-ID validation helpers (`utils/validate.py`).

### Changed
- `python-Wappalyzer` is now an **optional** extra (`pip install threattracer[asset]`);
  the base install is leaner and no longer breaks if Wappalyzer fails to build.
  Header/body fingerprinting still works without it.
- Nuclei client rewritten with bounded concurrency, config-driven metadata
  fetching, and a lock so concurrent CVEs in the same year hit GitHub once.
- HTTP client: `404` now means "no results" (returns `None`) instead of raising;
  added a public `raw_get()` so the asset scanner no longer pokes private internals.
- Atomic config writes; robust handling of corrupt config files.

### Fixed
- Malformed CVE IDs (`CVE-`, `NOTACVE`, empty) now degrade to empty results
  instead of raising `IndexError` deep in the network clients.
- Metasploit reference matching handles both `2021-44228` and `CVE-2021-44228`
  reference forms.
- Top-level CLI exceptions are caught and reported cleanly (no raw tracebacks);
  `Ctrl-C` exits with code 130.
