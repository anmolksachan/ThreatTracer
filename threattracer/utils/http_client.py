"""
threattracer.utils.http_client
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Shared async HTTP client with:
  - Exponential backoff retry (via tenacity)
  - 429 / Retry-After awareness
  - Configurable timeouts
  - Clean headers (no user-agent spoofing)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from threattracer.utils.config import AppConfig

log = logging.getLogger(__name__)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    return isinstance(exc, (httpx.TimeoutException, httpx.NetworkError))


class AsyncHTTPClient:
    """
    Thin wrapper around httpx.AsyncClient providing retry logic and
    a consistent set of default headers.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "AsyncHTTPClient":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._config.request_timeout),
            headers={"User-Agent": self._config.user_agent},
            follow_redirects=True,
            http2=True,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def get(
        self,
        url: str,
        params: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ) -> Optional[Any]:
        """
        Perform a GET request with retry logic.
        Returns parsed JSON dict/list or None on permanent failure.
        """
        assert self._client, "Client not open"
        headers = dict(extra_headers or {})

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._config.max_retries),
            wait=wait_exponential(
                multiplier=self._config.retry_base_delay, min=1, max=30
            ),
            retry=retry_if_exception(_is_retryable),
            reraise=False,
        ):
            with attempt:
                try:
                    resp = await self._client.get(
                        url, params=params, headers=headers
                    )
                    if resp.status_code == 429:
                        retry_after = int(resp.headers.get("Retry-After", "6"))
                        log.warning(
                            "Rate-limited by %s. Sleeping %ds.", url, retry_after
                        )
                        await asyncio.sleep(retry_after)
                        resp.raise_for_status()  # force retry
                    resp.raise_for_status()
                    return resp.json()
                except httpx.HTTPStatusError as exc:
                    log.debug(
                        "HTTP %d from %s", exc.response.status_code, url
                    )
                    raise
                except Exception as exc:
                    log.debug("Request error (%s): %s", type(exc).__name__, exc)
                    raise

        log.error("All retry attempts exhausted for %s", url)
        return None

    async def get_text(
        self,
        url: str,
        extra_headers: Optional[dict] = None,
    ) -> Optional[str]:
        """Like get() but returns raw text body."""
        assert self._client, "Client not open"
        headers = dict(extra_headers or {})
        try:
            resp = await self._client.get(url, headers=headers)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.text
        except Exception as exc:
            log.debug("get_text failed for %s: %s", url, exc)
            return None
