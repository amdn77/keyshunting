"""Fetch a block window of BSC and write NDJSON shards.

Each line: {"block_number": int, "timestamp": int, "txs": [...], "logs": [...]}
Uses JSON-RPC batch calls for throughput.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .rpc import RPCPool, endpoints_from_env

BATCH = 100


def fetch_window(pool: RPCPool, start: int, end: int, out_dir: Path, shard_blocks: int = 1000) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    ep = pool.endpoints[0]
    for shard_start in range(start, end + 1, shard_blocks):
        shard_end = min(shard_start + shard_blocks - 1, end)
        out_path = out_dir / f"blocks_{shard_start}_{shard_end}.ndjson"
        if out_path.exists():
            print(f"skip existing {out_path}")
            continue
        rows: list[str] = []
        for base in range(shard_start, shard_end + 1, BATCH):
            hi = min(base + BATCH - 1, shard_end)
            try:
                resp = pool.session.post(
                    ep,
                    json=[
                        {"jsonrpc": "2.0", "id": i, "method": "eth_getBlockByNumber", "params": [hex(base + i), True]}
                        for i in range(hi - base + 1)
                    ],
                    timeout=180,
                ).json()
            except Exception as e:
                print(f"batch getBlock failed @ {base}: {e}")
                continue
            nums = [int(b["result"]["number"], 16) for b in resp if isinstance(b, dict) and b.get("result")]
            if not nums:
                print(f"batch getBlock bad response @ {base}: {str(resp)[:200]}")
                continue
            try:
                resp2 = pool.session.post(
                    ep,
                    json=[
                        {"jsonrpc": "2.0", "id": i, "method": "eth_getBlockReceipts", "params": [hex(n)]}
                        for i, n in enumerate(nums)
                    ],
                    timeout=180,
                ).json()
            except Exception as e:
                print(f"batch receipts failed @ {base}: {e}")
                resp2 = []
            recs_by_block: dict[int, list] = {}
            for item in resp2:
                for r in item.get("result") or []:
                    try:
                        recs_by_block.setdefault(int(r["blockNumber"], 16), []).append(r)
                    except (KeyError, ValueError):
                        continue
            for b in resp:
                blk = b.get("result")
                if not blk:
                    continue
                try:
                    bn = int(blk["number"], 16)
                except (KeyError, ValueError):
                    continue
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
                rows.append(
                    json.dumps(
                        {"block_number": bn, "timestamp": int(blk["timestamp"], 16), "txs": txs, "logs": logs}
                    )
                )
            print(f"blocks {base}-{hi} fetched")
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
    p.add_argument("--env", default=".env")
    a = p.parse_args()
    pool = RPCPool(endpoints_from_env(a.env))
    fetch_window(pool, a.from_block, a.to_block, a.out, a.shard_blocks)


if __name__ == "__main__":
    main()
