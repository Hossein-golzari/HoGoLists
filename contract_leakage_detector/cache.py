"""
Local file-based cache for bytecode, proxy resolution, and analysis results.
All cache operations are synchronous internally but exposed as async via asyncio.to_thread
so they don't block the event loop.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

# Category names used as subdirectories
CAT_BYTECODE = "bytecode"
CAT_PROXY = "proxy"
CAT_ANALYSIS = "analysis"
CAT_STORAGE = "storage"


class LocalCache:
    """
    Two-level directory cache: <root>/<category>/<hash-based-filename>.json

    Keys are arbitrary strings (e.g. "0xABC:1:latest").
    Values must be JSON-serialisable.
    """

    def __init__(self, cache_dir: str) -> None:
        self.root = Path(cache_dir).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers (sync)
    # ------------------------------------------------------------------

    def _cat_dir(self, category: str) -> Path:
        d = self.root / category
        d.mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def _filename(key: str) -> str:
        digest = hashlib.sha256(key.encode()).hexdigest()[:24]
        # Append a short human-readable suffix for debuggability
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key[:24])
        return f"{digest}_{safe}.json"

    def _path(self, category: str, key: str) -> Path:
        return self._cat_dir(category) / self._filename(key)

    def _get_sync(self, category: str, key: str) -> Optional[Any]:
        path = self._path(category, key)
        if not path.exists():
            return None
        try:
            with open(path, "r") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log.debug("Cache read error for %s/%s: %s", category, key, exc)
            return None

    def _set_sync(self, category: str, key: str, value: Any) -> None:
        path = self._path(category, key)
        try:
            with open(path, "w") as fh:
                json.dump(value, fh, separators=(",", ":"))
        except OSError as exc:
            log.warning("Cache write error for %s/%s: %s", category, key, exc)

    def _delete_sync(self, category: str, key: str) -> None:
        path = self._path(category, key)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Async public API
    # ------------------------------------------------------------------

    async def get(self, category: str, key: str) -> Optional[Any]:
        return await asyncio.to_thread(self._get_sync, category, key)

    async def set(self, category: str, key: str, value: Any) -> None:
        await asyncio.to_thread(self._set_sync, category, key, value)

    async def delete(self, category: str, key: str) -> None:
        await asyncio.to_thread(self._delete_sync, category, key)

    # ------------------------------------------------------------------
    # Domain-specific helpers
    # ------------------------------------------------------------------

    @staticmethod
    def bytecode_key(address: str, chain_id: int, block: str) -> str:
        return f"{address.lower()}:{chain_id}:{block}"

    @staticmethod
    def proxy_key(address: str, chain_id: int, block: str) -> str:
        return f"proxy:{address.lower()}:{chain_id}:{block}"

    @staticmethod
    def analysis_key(address: str, chain_id: int, block: str) -> str:
        return f"analysis:{address.lower()}:{chain_id}:{block}"

    @staticmethod
    def storage_key(address: str, slot: str, chain_id: int, block: str) -> str:
        return f"storage:{address.lower()}:{slot}:{chain_id}:{block}"

    async def get_bytecode(self, address: str, chain_id: int, block: str) -> Optional[str]:
        return await self.get(CAT_BYTECODE, self.bytecode_key(address, chain_id, block))

    async def set_bytecode(self, address: str, chain_id: int, block: str, code: str) -> None:
        await self.set(CAT_BYTECODE, self.bytecode_key(address, chain_id, block), code)

    async def get_proxy(self, address: str, chain_id: int, block: str) -> Optional[Any]:
        return await self.get(CAT_PROXY, self.proxy_key(address, chain_id, block))

    async def set_proxy(self, address: str, chain_id: int, block: str, info: Any) -> None:
        await self.set(CAT_PROXY, self.proxy_key(address, chain_id, block), info)

    async def get_analysis(self, address: str, chain_id: int, block: str) -> Optional[Any]:
        return await self.get(CAT_ANALYSIS, self.analysis_key(address, chain_id, block))

    async def set_analysis(self, address: str, chain_id: int, block: str, result: Any) -> None:
        await self.set(CAT_ANALYSIS, self.analysis_key(address, chain_id, block), result)


class NullCache:
    """Drop-in replacement for LocalCache when no caching is desired."""

    async def get(self, *_: Any) -> None:
        return None

    async def set(self, *_: Any) -> None:
        return

    async def delete(self, *_: Any) -> None:
        return

    async def get_bytecode(self, *_: Any) -> None:
        return None

    async def set_bytecode(self, *_: Any) -> None:
        return

    async def get_proxy(self, *_: Any) -> None:
        return None

    async def set_proxy(self, *_: Any) -> None:
        return

    async def get_analysis(self, *_: Any) -> None:
        return None

    async def set_analysis(self, *_: Any) -> None:
        return
