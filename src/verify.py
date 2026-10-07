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


def are_eoas(addresses: list[str], env_path: str = ".env", batch: int = 100, workers: int = 8) -> dict[str, bool | None]:
    """Batch eth_getCode for many addresses; returns addr -> is_eoa."""
    eps = endpoints_from_env(env_path)
    if not eps:
        return {a: True for a in addresses}
    ep = eps[0]
    out: dict[str, bool | None] = {}
    chunks = [addresses[i : i + batch] for i in range(0, len(addresses), batch)]

    def fetch(chunk: list[str]):
        payload = [
            {"jsonrpc": "2.0", "id": i, "method": "eth_getCode", "params": [a, "latest"]}
            for i, a in enumerate(chunk)
        ]
        for attempt in range(5):
            try:
                resp = requests.post(ep, json=payload, timeout=60).json()
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
                    if not retry_needed or attempt == 4:
                        return res
                    time.sleep(min(2.0 * (attempt + 1), 15.0))
                    continue
            except Exception:
                time.sleep(min(2.0 * (attempt + 1), 15.0))
        return {a: None for a in chunk}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(fetch, chunks):
            out.update(res)
    return out
