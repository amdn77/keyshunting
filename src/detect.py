"""Poisoning detection over fetched shards.

Outputs:
  findings.csv   — one row per suspected poisoning interaction
  recipients.csv — per-EOA top recipients (frequent counterparties)
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# BEP-20 authentic tokens on BSC (mainnet) — extend as needed
AUTHENTIC_TOKENS = {
    "0x55d398326f99059ff775485246999027b3197955": "USDT",
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "USDC",
    "0xe9e7cea3dedca5984780bafc599bd69add087d56": "BUSD",
    "0x1af3f329e8be154074d8769d1ffa4dd5d58f5f5c": "DAI",
}


def hex_to_int(h: str) -> int:
    return int(h, 16) if h.startswith("0x") else int(h, 16)


def decode_transfer(log: dict) -> dict | None:
    topics = [t.lower() for t in log.get("topics", [])]
    if not topics or topics[0] != TRANSFER_TOPIC or len(topics) < 3:
        return None
    try:
        frm = "0x" + topics[1][-40:]
        to = "0x" + topics[2][-40:]
        data = log.get("data", "0x0")
        value = int(data, 16) if data else 0
    except (ValueError, TypeError):
        return None
    return {"token": log["address"].lower(), "from": frm, "to": to, "value": value, "tx_hash": log["tx_hash"]}


def similar(a: str, b: str) -> tuple[int, int]:
    a, b = a.lower().replace("0x", ""), b.lower().replace("0x", "")
    p = 0
    for x, y in zip(a, b):
        if x == y:
            p += 1
        else:
            break
    s = 0
    for x, y in zip(reversed(a), reversed(b)):
        if x == y:
            s += 1
        else:
            break
    return p, s


def looks_like(l: str, r: str) -> bool:
    if l == r:
        return False
    p, s = similar(l, r)
    return p >= 3 and s >= 4


def run(in_dir: Path, out_dir: Path, dust_wei: int = 10**15) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    # counterparty counts per EOA
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    # per victim: set of all counterparty addresses it has touched (tokens + native)
    touches: dict[str, set[str]] = defaultdict(set)
    # recorded transfer events involving each address pair for classification
    events: list[dict] = []

    for f in sorted(in_dir.glob("blocks_*.ndjson")):
        for line in open(f, encoding="utf-8"):
            blk = json.loads(line)
            for tx in blk["txs"]:
                frm, to, val = tx["from"].lower(), (tx.get("to") or "").lower(), tx["value"]
                if frm and to:
                    counts[frm][to] += 1
                    counts[to][frm] += 1
                    touches[frm].add(to)
                    touches[to].add(frm)
                    events.append({"kind": "native", "from": frm, "to": to, "value": val,
                                   "token": "BNB", "tx_hash": tx["hash"], "block": blk["block_number"]})
            for lg in blk["logs"]:
                tr = decode_transfer(lg)
                if tr is None:
                    continue
                frm, to = tr["from"], tr["to"]
                counts[frm][to] += 1
                counts[to][frm] += 1
                touches[frm].add(to)
                touches[to].add(frm)
                events.append({"kind": "token", "from": frm, "to": to, "value": tr["value"],
                               "token": tr["token"], "tx_hash": tr["tx_hash"], "block": blk["block_number"]})

    # recipients.csv: top recipients per EOA
    with open(out_dir / "recipients.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["eoa", "recipient", "count"])
        for eoa, recs in counts.items():
            for rec, c in sorted(recs.items(), key=lambda kv: -kv[1])[:20]:
                w.writerow([eoa, rec, c])

    # index events by sender/receiver for lookalike checks
    by_addr: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_addr[e["from"]].append(e)
        by_addr[e["to"]].append(e)

    findings = []
    for victim, peers in touches.items():
        peers = list(peers)
        # pre-compute lookalike pairs among peers
        for i, r in enumerate(peers):
            for l in peers[i + 1 :]:
                if looks_like(l, r):
                    for e in by_addr.get(victim, []):
                        pass
        # cheaper: for each event touching victim, check the counterparty against all other peers
        for e in by_addr.get(victim, []):
            other = e["to"] if e["from"] == victim else e["from"]
            for r in peers:
                if r == other or not looks_like(other, r):
                    continue
                attack = None
                token_auth = e["token"] in AUTHENTIC_TOKENS or e["token"] == "BNB"
                if e["kind"] == "token" and e["value"] == 0:
                    attack = "zero_value"
                elif e["kind"] == "native" and e["value"] < dust_wei:
                    attack = "tiny_native"
                elif e["kind"] == "token" and e["value"] < 10**6:  # sub-cent USDT/USDC style
                    attack = "tiny_token"
                elif e["kind"] == "token" and not token_auth:
                    attack = "counterfeit_token"
                if attack is None:
                    continue
                findings.append(
                    {
                        "victim": victim,
                        "counterparty": r,
                        "lookalike": other,
                        "attack": attack,
                        "token": e["token"],
                        "value": e["value"],
                        "tx_hash": e["tx_hash"],
                        "block": e["block"],
                    }
                )

    with open(out_dir / "findings.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["victim", "counterparty", "lookalike", "attack", "token", "value", "tx_hash", "block"])
        w.writeheader()
        w.writerows(findings)
    print(f"findings={len(findings)}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="in_dir", type=Path, default=Path("shards"))
    p.add_argument("--out", dest="out_dir", type=Path, default=Path("findings"))
    a = p.parse_args()
    run(a.in_dir, a.out_dir)


if __name__ == "__main__":
    main()
