"""
threattracer.core.llm_summary
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Optional, fully-local natural-language summariser for scan results.

Design goals
------------
* **Optional & offline** — talks to a *local* model daemon you already run
  (Ollama or any OpenAI-compatible server such as llama.cpp, LM Studio, vLLM).
  No data leaves your machine, no cloud key required.
* **Never fatal** — if no model is reachable, if it times out, or if it returns
  garbage, we transparently fall back to a deterministic template summary.  A
  scan must never crash because the LLM is unavailable.
* **Defensive framing** — the model is asked to produce a *triage briefing*
  (what to patch/verify first and why), built from the deterministic triage
  scores.  It is not asked to write or improve exploit code.

The summariser consumes a :class:`ScanSummary` (see ``core.triage``) so it works
identically for component, CPE, CVE, and asset scans.
"""

from __future__ import annotations


import json
import logging
from typing import List, Optional

import httpx

from threattracer.utils.config import AppConfig
from threattracer.utils.models import LLMSummary, ScanSummary, TriageItem

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a senior vulnerability-management analyst writing a concise triage "
    "briefing for an authorised penetration tester or blue-team engineer. "
    "You are given structured scan findings that were assembled from public "
    "sources (NVD, EPSS, CISA KEV, Exploit-DB, Nuclei, Metasploit metadata). "
    "Write a short, professional briefing that: (1) states the overall risk "
    "posture in one or two sentences, (2) names the specific CVEs that should be "
    "investigated or patched first and clearly explains why using the provided "
    "signals, and (3) gives brief, defensive next steps (verification, patching, "
    "mitigation, monitoring). Do NOT invent CVEs, scores, or facts not present in "
    "the data. Do NOT write, complete, or improve exploit code. Keep it under "
    "220 words. Use plain prose and short bullet points where helpful."
)


# ── prompt construction ────────────────────────────────────────────────────

def _summary_to_prompt(summary: ScanSummary, max_items: int) -> str:
    lines: List[str] = []
    lines.append(f"Target: {summary.target or 'N/A'}  (scan type: {summary.scan_type})")
    lines.append(
        "Totals: "
        f"{summary.total_cves} CVEs | critical {summary.critical} | high {summary.high} | "
        f"medium {summary.medium} | low {summary.low}"
    )
    lines.append(
        "Exploitation signals: "
        f"in CISA KEV {summary.in_kev} | ransomware-linked {summary.ransomware_linked} | "
        f"Exploit-DB {summary.with_edb} | public PoC {summary.with_poc} | "
        f"Nuclei templates {summary.with_nuclei} | Metasploit modules {summary.with_msf} | "
        f"weaponised {summary.weaponised}"
    )
    lines.append("")
    lines.append("Highest-priority findings (deterministic triage score, 0-100):")
    for item in summary.top_findings[:max_items]:
        cvss = f"{item.cvss_score:.1f}" if item.cvss_score is not None else "n/a"
        epss = f"{item.epss_score * 100:.0f}%" if item.epss_score is not None else "n/a"
        comp = f" [{item.component}]" if item.component else ""
        sig = ", ".join(item.signals) if item.signals else "none"
        lines.append(
            f"- {item.cve_id}{comp}: priority {item.priority_score:.0f}, "
            f"severity {item.severity.value}, CVSS {cvss}, EPSS {epss}, "
            f"maturity {item.exploit_maturity}; signals: {sig}"
        )
    if not summary.top_findings:
        lines.append("- (no CVEs found)")
    lines.append("")
    lines.append("Write the triage briefing now.")
    return "\n".join(lines)


# ── deterministic fallback ─────────────────────────────────────────────────

def heuristic_summary(summary: ScanSummary) -> str:
    """A readable, fact-based briefing built purely from the triage data."""
    if summary.total_cves == 0:
        return (
            f"No CVEs were identified for {summary.target or 'the target'}. "
            "Either the detected components are current, no version was resolvable, "
            "or the affected products are not tracked in NVD. Re-run with a GitHub "
            "token and an NVD API key for the most complete coverage."
        )

    parts: List[str] = []

    # 1. posture
    if summary.in_kev or summary.weaponised:
        posture = "HIGH"
    elif summary.critical or summary.high:
        posture = "ELEVATED"
    else:
        posture = "MODERATE"
    parts.append(
        f"Overall risk posture for {summary.target or 'the target'}: {posture}. "
        f"Found {summary.total_cves} CVEs "
        f"({summary.critical} critical, {summary.high} high). "
        f"{summary.in_kev} are in the CISA KEV catalog "
        f"({summary.ransomware_linked} ransomware-linked), and {summary.weaponised} "
        f"have ready weaponisation (Metasploit module or confirmed in-the-wild use)."
    )

    # 2. what to look at first
    top = summary.top_findings[:5]
    if top:
        parts.append("\nInvestigate / remediate first:")
        bullets = []
        for item in top:
            comp = f" ({item.component})" if item.component else ""
            bullets.append(f"  • {item.cve_id}{comp} — {item.reason} [priority {item.priority_score:.0f}/100]")
        parts.append("\n".join(bullets))

    # 3. defensive next steps
    steps: List[str] = []
    if summary.in_kev:
        steps.append("prioritise KEV entries — they meet CISA BOD 22-01 remediation timelines")
    if summary.with_nuclei:
        steps.append("confirm exposure safely with the matching Nuclei templates before patching")
    if summary.weaponised:
        steps.append("treat weaponised items as time-critical; patch or isolate the affected service")
    steps.append("record findings against your asset inventory and re-scan after remediation")
    parts.append("\nNext steps: " + "; ".join(steps) + ".")

    return "\n".join(parts)


# ── LLM client ─────────────────────────────────────────────────────────────

class LLMSummariser:
    """
    Produces an :class:`LLMSummary` from a :class:`ScanSummary`.

    Usage::

        summariser = LLMSummariser(config)
        result = await summariser.summarise(scan_summary)
        print(result.text)          # always populated
        print(result.engine)        # 'ollama' | 'openai' | 'heuristic'
    """

    def __init__(self, config: AppConfig) -> None:
        self._cfg = config

    async def summarise(self, summary: ScanSummary) -> LLMSummary:
        provider = (self._cfg.llm_provider or "auto").lower()

        if provider == "off":
            return LLMSummary(text=heuristic_summary(summary), engine="heuristic")

        prompt = _summary_to_prompt(summary, self._cfg.llm_max_cves_in_prompt)

        # Decide which backends to try, in order.
        candidates: List[str] = []
        if provider == "ollama":
            candidates = ["ollama"]
        elif provider == "openai":
            candidates = ["openai"]
        else:  # auto
            candidates = ["ollama", "openai"]

        last_note: Optional[str] = None
        for engine in candidates:
            try:
                if engine == "ollama":
                    text = await self._call_ollama(prompt)
                else:
                    text = await self._call_openai(prompt)
                if text and text.strip():
                    return LLMSummary(
                        text=text.strip(),
                        engine=engine,
                        model=self._cfg.llm_model,
                    )
                last_note = f"{engine} returned an empty response"
            except _LLMUnavailable as exc:
                last_note = str(exc)
                log.debug("LLM backend '%s' unavailable: %s", engine, exc)
            except Exception as exc:  # noqa: BLE001 — must never propagate
                last_note = f"{engine} error: {type(exc).__name__}: {exc}"
                log.debug("LLM backend '%s' failed: %s", engine, exc)

        # Everything failed → deterministic fallback.
        return LLMSummary(
            text=heuristic_summary(summary),
            engine="heuristic",
            degraded=True,
            note=last_note or "no local LLM reachable",
        )

    # ── availability probe (used by the `doctor` command) ──────────────

    async def probe(self) -> dict:
        """Return which local LLM backends are reachable. Never raises."""
        status = {"ollama": False, "openai": False, "model": self._cfg.llm_model}
        async with httpx.AsyncClient(timeout=5) as client:
            try:
                r = await client.get(f"{self._cfg.llm_ollama_url}/api/tags")
                status["ollama"] = r.status_code == 200
            except Exception:
                status["ollama"] = False
            try:
                r = await client.get(f"{self._cfg.llm_openai_url}/v1/models")
                status["openai"] = r.status_code == 200
            except Exception:
                status["openai"] = False
        return status

    # ── backends ───────────────────────────────────────────────────────

    async def _call_ollama(self, prompt: str) -> str:
        base = self._cfg.llm_ollama_url.rstrip("/")
        payload = {
            "model": self._cfg.llm_model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.2},
        }
        async with httpx.AsyncClient(timeout=self._cfg.llm_timeout) as client:
            try:
                resp = await client.post(f"{base}/api/chat", json=payload)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                raise _LLMUnavailable(f"cannot reach Ollama at {base}") from exc
            if resp.status_code == 404:
                raise _LLMUnavailable(
                    f"Ollama has no model '{self._cfg.llm_model}' "
                    f"(pull it with: ollama pull {self._cfg.llm_model})"
                )
            resp.raise_for_status()
            data = resp.json()
        # Non-streaming chat response
        msg = (data or {}).get("message") or {}
        return msg.get("content", "") or (data or {}).get("response", "")

    async def _call_openai(self, prompt: str) -> str:
        base = self._cfg.llm_openai_url.rstrip("/")
        headers = {"Content-Type": "application/json"}
        if self._cfg.llm_openai_key:
            headers["Authorization"] = f"Bearer {self._cfg.llm_openai_key}"
        payload = {
            "model": self._cfg.llm_model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 600,
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=self._cfg.llm_timeout) as client:
            try:
                resp = await client.post(
                    f"{base}/v1/chat/completions", json=payload, headers=headers
                )
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                raise _LLMUnavailable(
                    f"cannot reach OpenAI-compatible server at {base}"
                ) from exc
            resp.raise_for_status()
            data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise _LLMUnavailable(
                f"unexpected response shape from {base}: {json.dumps(data)[:160]}"
            ) from exc


class _LLMUnavailable(Exception):
    """Internal signal that a backend is simply not there (expected, not an error)."""
