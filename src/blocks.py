"""Fetch a block window of BSC and write NDJSON shards (parallel).

Each line: {"block_number": int, "timestamp": int, "txs": [...], "logs": [...]}
Uses a thread pool over block batches with JSON-RPC batch calls and
rate-limit retry/backoff.
"""
from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .rpc import RPCPool, endpoints_from_env

BATCH = 50
WORKERS = 6


def fetch_batch(pool: RPCPool, base: int, hi: int) -> list[str] | None:
    ep = pool.endpoints[0]
    for attempt in range(8):
        try:
            resp = pool.session.post(
                ep,
                json=[
                    {"jsonrpc": "2.0", "id": i, "method": "eth_getBlockByNumber", "params": [hex(base + i), True]}
                    for i in range(hi - base + 1)
                ],
                timeout=180,
            ).json()
            if isinstance(resp, list) and all(isinstance(b, dict) and b.get("result") for b in resp):
                break
            time.sleep(min(2.0 * (attempt + 1), 30.0))
        except Exception as e:
            print(f"getBlock retry @ {base}: {e}")
            time.sleep(min(2.0 * (attempt + 1), 30.0))
    else:
        print(f"getBlock failed @ {base}")
        return None
    nums = [int(b["result"]["number"], 16) for b in resp]
    for attempt in range(8):
        try:
            resp2 = pool.session.post(
                ep,
                json=[
                    {"jsonrpc": "2.0", "id": i, "method": "eth_getBlockReceipts", "params": [hex(n)]}
                    for i, n in enumerate(nums)
                ],
                timeout=180,
            ).json()
            if isinstance(resp2, list) and all(isinstance(b, dict) and ("result" in b) for b in resp2):
                break
            time.sleep(min(2.0 * (attempt + 1), 30.0))
        except Exception as e:
            print(f"receipts retry @ {base}: {e}")
            time.sleep(min(2.0 * (attempt + 1), 30.0))
    else:
        print(f"receipts failed @ {base}")
        return None
    recs_by_block: dict[int, list] = {}
    for item in resp2:
        for r in item.get("result") or []:
            try:
                recs_by_block.setdefault(int(r["blockNumber"], 16), []).append(r)
            except (KeyError, ValueError):
                continue
    rows: list[str] = []
    for b in resp:
        blk = b["result"]
        bn = int(blk["number"], 16)
        logs = []
        for r in recs_by_block.get(bn, []):
            for lg in r.get("logs", []) or []:
                logs.append(
                    {
                        "address": lg["address"],
                        "topics": lg["topics"],
                        "data": lg["data"],
                        "tx_hash": lg["transactionHash"],
                        "log_index": int(lg.get("logIndex", "0x0"), 16),
                    }
                )
        txs = [
            {
                "hash": tx["hash"],
                "from": tx["from"],
                "to": tx.get("to"),
                "value": int(tx.get("value", "0x0"), 16),
                "input": tx.get("input", "0x"),
            }
            for tx in (blk.get("transactions", []) or [])
        ]
        rows.append(json.dumps({"block_number": bn, "timestamp": int(blk["timestamp"], 16), "txs": txs, "logs": logs}))
    return rows


def fetch_window(pool: RPCPool, start: int, end: int, out_dir: Path, shard_blocks: int = 1000, workers: int = WORKERS) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    # partition into shard files of shard_blocks each, and process batches of BATCH across shards
    for shard_start in range(start, end + 1, shard_blocks):
        shard_end = min(shard_start + shard_blocks - 1, end)
        out_path = out_dir / f"blocks_{shard_start}_{shard_end}.ndjson"
        if out_path.exists():
            print(f"skip existing {out_path}")
            continue
        # build list of (base, hi) batches for this shard
        batches = []
        for base in range(shard_start, shard_end + 1, BATCH):
            batches.append((base, min(base + BATCH - 1, shard_end)))
        rows: list[str] = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for result in ex.map(lambda b: fetch_batch(pool, b[0], b[1]), batches, chunksize=1):
                if result:
                    rows.extend(result)
                    print(f"batch done ({len(rows)}/{shard_end-shard_start+1} blocks so far)")
        # sort rows by block number
        rows.sort(key=lambda line: json.loads(line)["block_number"])
        with open(out_path, "w", encoding="utf-8") as f:
            for line in rows:
                f.write(line + "\n")
        print(f"wrote {out_path} ({len(rows)} blocks)")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--from-block", type=int, required=True)
    p.add_argument("--to-block", type=int, required=True)
    p.add_argument("--out", type=Path, default=Path("shards"))
    p.add_argument("--shard-blocks", type=int, default=1000)
    p.add_argument("--workers", type=int, default=WORKERS)
    p.add_argument("--env", default=".env")
    a = p.parse_args()
    pool = RPCPool(endpoints_from_env(a.env))
    fetch_window(pool, a.from_block, a.to_block, a.out, a.shard_blocks, a.workers)


if __name__ == "__main__":
    main()
