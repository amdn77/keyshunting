"""Multi-endpoint BSC JSON-RPC client with retry/failover and simple rate limiting."""
from __future__ import annotations

import itertools
import os
import random
import threading
import time
from typing import Any, Iterable

import requests
from requests.adapters import HTTPAdapter

DEFAULT_PUBLIC = [
    "https://bsc-dataseed.binance.org",
    "https://bsc-dataseed1.defibit.io",
    "https://bsc-dataseed1.ninicoin.io",
]


def _split(val: str | None) -> list[str]:
    if not val:
        return []
    return [v.strip() for v in val.replace("\n", ",").split(",") if v.strip()]


def endpoints_from_env(env_path: str = ".env") -> list[str]:
    eps: list[str] = []
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip().endswith("_BSC") or ("BSC" in k.upper() and "URL" in k.upper()) or "BLOCK_PI" in k.upper() or "BLOCKPI" in k.upper():
                eps.extend(_split(v))
    eps.extend(_split(os.environ.get("BSC_ALCHEMY_URL")))
    for k in ("BLOCKPI_BSC", "NODEREAL_BSC", "PUBLIC_BSC", "BSC_RPC_URL"):
        eps.extend(_split(os.environ.get(k)))
    if not eps:
        eps = list(DEFAULT_PUBLIC)
    # de-duplicate, keep order
    seen, out = set(), []
    for e in eps:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


class RPCPool:
    def __init__(self, endpoints: Iterable[str], timeout: float = 30.0, max_retries: int = 5):
        self.endpoints = list(endpoints)
        self.timeout = timeout
        self.max_retries = max_retries
        self._cycle = itertools.cycle(range(len(self.endpoints)))
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(pool_connections=32, pool_maxsize=32))

    def _next(self) -> int:
        with self._lock:
            return next(self._cycle)

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        params = params or []
        last_err: Exception | None = None
        for attempt in range(self.max_retries):
            idx = self._next()
            url = self.endpoints[idx]
            try:
                r = self.session.post(
                    url,
                    json={"jsonrpc": "2.0", "id": random.randint(1, 1 << 30), "method": method, "params": params},
                    timeout=self.timeout,
                )
                if r.status_code == 429:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                r.raise_for_status()
                data = r.json()
                if "error" in data and data["error"] is not None:
                    raise RuntimeError(f"{method}: {data['error']}")
                return data["result"]
            except Exception as e:  # noqa: BLE001
                last_err = e
                time.sleep(min(2.0 * (attempt + 1), 8.0))
        raise RuntimeError(f"RPC call failed after {self.max_retries} retries: {method}: {last_err}")

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def block_by_number(self, n: int, full_txs: bool = True) -> dict:
        return self.call("eth_getBlockByNumber", [hex(n), full_txs])

    def receipts_by_block(self, n: int) -> list[dict]:
        try:
            return self.call("eth_getBlockReceipts", [hex(n)]) or []
        except RuntimeError:
            return []
