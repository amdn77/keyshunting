"""EOA verification: return True if the address has no contract code."""
from __future__ import annotations

import os
import random
import time

import requests

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
