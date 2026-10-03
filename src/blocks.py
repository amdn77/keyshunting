"""Fetch a block window of BSC and write NDJSON shards.

Each line: {"block_number": int, "timestamp": int, "txs": [{from,to,value,hash,input}], "logs": [{address,topics,data,tx_hash,log_index}]}
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .rpc import RPCPool, endpoints_from_env


def fetch_window(pool: RPCPool, start: int, end: int, out_dir: Path, shard_blocks: int = 1000) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for shard_start in range(start, end + 1, shard_blocks):
        shard_end = min(shard_start + shard_blocks - 1, end)
        out_path = out_dir / f"blocks_{shard_start}_{shard_end}.ndjson"
        if out_path.exists():
            print(f"skip existing {out_path}")
            continue
        with open(out_path, "w", encoding="utf-8") as f:
            for n in range(shard_start, shard_end + 1):
                try:
                    blk = pool.block_by_number(n, full_txs=True)
                except RuntimeError as e:
                    print(f"block {n} fetch failed: {e}")
                    continue
                if not blk:
                    continue
                receipts = pool.receipts_by_block(n)
                if not receipts:
                    receipts = []
                    for tx in blk.get("transactions", []) or []:
                        try:
                            r = pool.call("eth_getTransactionReceipt", [tx["hash"]])
                        except RuntimeError:
                            r = None
                        if r:
                            receipts.append(r)
                logs = []
                for r in receipts:
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
                f.write(
                    json.dumps(
                        {
                            "block_number": n,
                            "timestamp": int(blk["timestamp"], 16),
                            "txs": txs,
                            "logs": logs,
                        }
                    )
                    + "\n"
                )
                if n % 100 == 0:
                    print(f"block {n}")
        print(f"wrote {out_path}")


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
