"""EOA verification: return True if the address has no contract code."""
from __future__ import annotations

import random
import time

import requests
from concurrent.futures import ThreadPoolExecutor

from .rpc import endpoints_from_env


def code_for(address: str, env_path: str = ".env") -> str | None:
    eps = endpoints_from_env(env_path)
    for ep in eps:
        for attempt in range(3):
            try:
                r = requests.post(
                    ep,
                    json={"jsonrpc": "2.0", "id": random.randint(1, 1 << 30), "method": "eth_getCode", "params": [address, "latest"]},
                    timeout=20,
                ).json()
                if r.get("result") is not None:
                    return r["result"]
            except Exception:
                time.sleep(0.3)
    return None


def is_eoa(address: str, env_path: str = ".env") -> bool:
    code = code_for(address, env_path)
    return code in ("0x", "0x0")


def are_eoas(
    addresses: list[str],
    env_path: str = ".env",
    batch: int = 100,
    workers: int = 16,
    attempts: int = 3,
) -> dict[str, bool | None]:
    """Batch eth_getCode for many addresses; returns addr -> True/False/None(unknown).

    Chunks are spread round-robin across all configured endpoints to avoid
    per-endpoint rate limits. Unknown results are kept (never dropped).
    """
    eps = endpoints_from_env(env_path)
    if not eps:
        return {a: True for a in addresses}
    out: dict[str, bool | None] = {}
    chunks = [(i, addresses[i : i + batch]) for i in range(0, len(addresses), batch)]

    def fetch(task: tuple[int, list[str]]):
        idx, chunk = task
        ep = eps[idx % len(eps)]
        payload = [
            {"jsonrpc": "2.0", "id": i, "method": "eth_getCode", "params": [a, "latest"]}
            for i, a in enumerate(chunk)
        ]
        for attempt in range(attempts):
            try:
                resp = requests.post(ep, json=payload, timeout=45).json()
                if isinstance(resp, list):
                    by_id = {r.get("id"): r for r in resp if isinstance(r, dict)}
                    res: dict[str, bool | None] = {}
                    retry_needed = False
                    for i, a in enumerate(chunk):
                        item = by_id.get(i)
                        if not item or "error" in item or item.get("result") is None:
                            res[a] = None  # unknown -> keep
                            retry_needed = True
                            continue
                        code = item.get("result")
                        res[a] = code in ("0x", "0x0")
                    if not retry_needed or attempt == attempts - 1:
                        return res
                    time.sleep(min(1.0 * (attempt + 1), 4.0))
                    continue
            except Exception:
                time.sleep(min(1.0 * (attempt + 1), 4.0))
        return {a: None for a in chunk}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(fetch, chunks, chunksize=4):
            out.update(res)
    return out
