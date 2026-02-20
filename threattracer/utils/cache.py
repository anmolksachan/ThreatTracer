"""
threattracer.utils.cache
~~~~~~~~~~~~~~~~~~~~~~~~
Async SQLite-backed response cache with TTL expiry.

Usage::

    async with ResponseCache(config) as cache:
        val = await cache.get("nvd:CVE-2021-44228")
        if val is None:
            val = await fetch_something()
            await cache.set("nvd:CVE-2021-44228", val)
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from threattracer.utils.config import AppConfig

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key       TEXT PRIMARY KEY,
    value     TEXT NOT NULL,
    stored_at REAL NOT NULL
);
"""


class ResponseCache:
    """Async context-manager-based SQLite cache."""

    def __init__(self, config: AppConfig) -> None:
        self._path = config.cache_db_path
        self._ttl = config.cache_ttl_seconds
        self._db: Optional[aiosqlite.Connection] = None

    async def __aenter__(self) -> "ResponseCache":
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._path)
        await self._db.execute(_SCHEMA)
        await self._db.commit()
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._db:
            await self._db.close()

    async def get(self, key: str) -> Optional[Any]:
        """Return cached value or None if missing / expired."""
        assert self._db, "Cache not opened"
        async with self._db.execute(
            "SELECT value, stored_at FROM cache WHERE key = ?", (key,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        value_raw, stored_at = row
        if time.time() - stored_at > self._ttl:
            await self.delete(key)
            return None
        try:
            return json.loads(value_raw)
        except json.JSONDecodeError:
            return value_raw

    async def set(self, key: str, value: Any) -> None:
        """Store value under key."""
        assert self._db, "Cache not opened"
        serialised = json.dumps(value)
        await self._db.execute(
            "INSERT OR REPLACE INTO cache (key, value, stored_at) VALUES (?, ?, ?)",
            (key, serialised, time.time()),
        )
        await self._db.commit()

    async def delete(self, key: str) -> None:
        assert self._db, "Cache not opened"
        await self._db.execute("DELETE FROM cache WHERE key = ?", (key,))
        await self._db.commit()

    async def purge_expired(self) -> int:
        """Delete all expired entries, return count removed."""
        assert self._db, "Cache not opened"
        cutoff = time.time() - self._ttl
        async with self._db.execute(
            "DELETE FROM cache WHERE stored_at < ? RETURNING key", (cutoff,)
        ) as cur:
            rows = await cur.fetchall()
        await self._db.commit()
        n = len(rows)
        if n:
            log.debug("Purged %d expired cache entries", n)
        return n

    async def clear_all(self) -> None:
        assert self._db, "Cache not opened"
        await self._db.execute("DELETE FROM cache")
        await self._db.commit()
