"""Log-based resumable streaming scanner for BSC address-poisoning detection.

Fetches ERC-20/BEP-20 Transfer logs via eth_getLogs in chunks, aggregates
counterparties per address, detects lookalike (prefix>=4, suffix>=5) poisoning
events, and appends compact findings to CSV. Designed for GitHub Actions:
  * time-budgeted (never exceeds the CI job limit)
  * resumable via a progress JSON file
  * bounded memory (capped peer index)

Usage:
  python -m src.logs_scan --shard 2023s01 --from-block A --to-block B \
      --state state/2023s01.json --results results/ --time-budget 14400
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .rpc import RPCPool, endpoints_from_env

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
AUTHENTIC_TOKENS = {
    "0x55d398326f99059ff775485246999027b3197955": "USDT",
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "USDC",
    "0xe9e7cea3dedca5984780bafc599bd69add087d56": "BUSD",
    "0x1af3f329e8be154074d8769d1ffa4dd5d58f5f5c": "DAI",
}
ZERO_LIKE = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}
TINY_TOKEN = 10**15  # < 0.001 token units (typically sub-cent)


def norm(a: str) -> str:
    return a.lower().replace("0x", "")


def decode_transfer(log: dict) -> tuple[str, str, str, int, str] | None:
    """Return (token, from, to, value, tx_hash) or None."""
    topics = [t.lower() for t in log.get("topics", [])]
    if not topics or topics[0] != TRANSFER_TOPIC or len(topics) < 3:
        return None
    try:
        frm = "0x" + topics[1][-40:]
        to = "0x" + topics[2][-40:]
        data = log.get("data", "0x0")
        value = int(data, 16) if data and data != "0x" else 0
    except (ValueError, TypeError):
        return None
    return log["address"].lower(), frm, to, value, log.get("transactionHash", "")


def fetch_range(pool: RPCPool, ep: str, base: int, hi: int) -> list[dict] | None:
    """Fetch all Transfer logs for [base, hi] with retry/backoff; adaptive shrink."""
    span = hi - base + 1
    cur = base
    out: list[dict] = []
    while cur <= hi:
        end = min(cur + span - 1, hi)
        for attempt in range(6):
            try:
                r = pool.session.post(
                    ep,
                    json=[
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "eth_getLogs",
                            "params": [
                                {"fromBlock": hex(cur), "toBlock": hex(end), "topics": [TRANSFER_TOPIC]}
                            ],
                        }
                    ],
                    timeout=180,
                ).json()
                res = r[0].get("result") if isinstance(r, list) else r.get("result")
                if res is not None:
                    out.extend(res)
                    cur = end + 1
                    break
                time.sleep(min(2.0 * (attempt + 1), 20.0))
            except Exception:
                time.sleep(min(2.0 * (attempt + 1), 20.0))
        else:
            # shrink span and retry
            if span > 100:
                span = max(100, span // 2)
                continue
            return None
    return out


def classify(token: str, value: int) -> str | None:
    if value == 0:
        return "zero_value"
    if token in AUTHENTIC_TOKENS:
        if value < TINY_TOKEN:
            return "tiny_token"
        return None
    # counterfeit / unknown token only counts as poisoning when paired with lookalike
    return "counterfeit_token"


def process_window(events: list[tuple[str, str, str, int, str]], peers: dict, max_peers: int = 12):
    """events: list of (token, from, to, value, tx_hash). Returns findings + new counts."""
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for token, frm, to, value, tx in events:
        if frm in ZERO_LIKE or to in ZERO_LIKE:
            continue
        counts[frm][to] += 1
        counts[to][frm] += 1
        # keep only limited peers per address to bound memory
    for a, cs in counts.items():
        if len(cs) > 200:
            counts[a] = dict(sorted(cs.items(), key=lambda kv: -kv[1])[:200])

    # merge with carry-over peer index for lookalike matching
    merged: dict[str, dict[str, int]] = {}
    for a in set(counts) | set(peers):
        d = dict(peers.get(a, {}))
        for r, c in counts.get(a, {}).items():
            d[r] = d.get(r, 0) + c
        if len(d) > max_peers:
            d = dict(sorted(d.items(), key=lambda kv: -kv[1])[:max_peers])
        merged[a] = d

    findings = []
    seen: set[tuple] = set()
    for token, frm, to, value, tx in events:
        if frm in ZERO_LIKE or to in ZERO_LIKE:
            continue
        attack = classify(token, value)
        if attack is None:
            continue
        for victim, other in ((frm, to), (to, frm)):
            pdata = merged.get(victim)
            if not pdata:
                continue
            on = norm(other)
            key3, key5 = on[:4], on[-5:]
            for r in pdata:
                if r == other:
                    continue
                rn = norm(r)
                if rn[:4] == key3 and rn[-5:] == key5:
                    key = (victim, r, other, attack, tx)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        {
                            "victim": victim,
                            "counterparty": r,
                            "lookalike": other,
                            "attack": attack,
                            "token": token,
                            "value": value,
                            "tx_hash": tx,
                        }
                    )
    return findings


def append_rows(path: Path, header: list[str], rows: list[list]) -> None:
    new = not path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerows(rows)


def run(
    shard: str,
    from_block: int,
    to_block: int,
    state_path: Path,
    results_dir: Path,
    time_budget: int,
    chunk: int = 1000,
    workers: int = 4,
    window: int = 10000,
) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)
    state = {"shard": shard, "next_block": from_block, "done": False}
    if state_path.exists():
        try:
            state.update(json.loads(state_path.read_text()))
        except Exception:
            pass
    next_block = max(int(state.get("next_block", from_block)), from_block)
    started = time.time()
    pool = RPCPool(endpoints_from_env())
    ep = pool.endpoints[0]

    findings_path = results_dir / f"{shard}_findings.csv"
    recipients_path = results_dir / f"{shard}_recipients.csv"
    peers: dict[str, dict[str, int]] = {}
    total_findings = 0

    while next_block <= to_block:
        elapsed = time.time() - started
        if elapsed > time_budget:
            print(f"time budget reached after {elapsed:.0f}s")
            break
        w_end = min(next_block + window - 1, to_block)
        # fetch chunks concurrently
        bases = list(range(next_block, w_end + 1, chunk))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(lambda b: fetch_range(pool, ep, b, min(b + chunk - 1, w_end)), bases))
        events: list[tuple[str, str, str, int, str]] = []
        for r in results:
            if not r:
                continue
            for lg in r:
                tr = decode_transfer(lg)
                if tr:
                    events.append(tr)
        findings = process_window(events, peers)
        if findings:
            rows = [
                [f["victim"], f["counterparty"], f["lookalike"], f["attack"], f["token"], f["value"], f["tx_hash"]]
                for f in findings
            ]
            append_rows(
                findings_path,
                ["victim", "counterparty", "lookalike", "attack", "token", "value", "tx_hash"],
                rows,
            )
            # side-by-side recipients per victim
            vics = {f["victim"] for f in findings}
            rec_rows = []
            for v in vics:
                for rec, c in sorted(peers.get(v, {}).items(), key=lambda kv: -kv[1])[:10]:
                    rec_rows.append([v, rec, c])
            if rec_rows:
                append_rows(recipients_path, ["eoa", "recipient", "count"], rec_rows)
            total_findings += len(findings)
        # update bounded carry-over peer index
        new_index: dict[str, dict[str, int]] = {}
        for token, frm, to, value, tx in events:
            if frm in ZERO_LIKE or to in ZERO_LIKE:
                continue
            new_index.setdefault(frm, {})[to] = new_index.get(frm, {}).get(to, 0) + 1
            new_index.setdefault(to, {})[frm] = new_index.get(to, {}).get(frm, 0) + 1
        for a, cs in new_index.items():
            d = peers.get(a, {})
            for r, c in cs.items():
                d[r] = d.get(r, 0) + c
            if len(d) > 12:
                d = dict(sorted(d.items(), key=lambda kv: -kv[1])[:12])
            peers[a] = d
        # cap total tracked addresses (memory bound)
        if len(peers) > 4_000_000:
            peers = dict(list(peers.items())[:4_000_000])
        next_block = w_end + 1
        state.update({"next_block": next_block, "done": next_block > to_block, "updated": int(time.time())})
        state_path.write_text(json.dumps(state))
        print(f"{shard}: window done at {w_end}, next={next_block}, findings_total={total_findings}")
    state.update({"next_block": next_block, "done": next_block > to_block, "updated": int(time.time())})
    state_path.write_text(json.dumps(state))
    print(f"{shard}: stopped at {next_block} (done={state['done']}), findings={total_findings}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--shard", required=True)
    p.add_argument("--from-block", type=int, required=True)
    p.add_argument("--to-block", type=int, required=True)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--results", type=Path, default=Path("results"))
    p.add_argument("--time-budget", type=int, default=14400)
    p.add_argument("--chunk", type=int, default=1000)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--window", type=int, default=10000)
    a = p.parse_args()
    run(a.shard, a.from_block, a.to_block, a.state, a.results, a.time_budget, a.chunk, a.workers, a.window)


if __name__ == "__main__":
    main()
