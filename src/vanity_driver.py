"""Vanity lookalike generation driver.

Reads critical_targets.csv, applies tiered difficulty by victim rank, runs the
compiled `vanity` binary (libsecp256k1) across a process pool, and appends
results to a shard CSV.

Tiers (by global victim rank):
  strong : rank < --strong-count           attempts [(4,3,180s), (3,3,90s), (3,2,30s)]
  medium : rank < strong + --medium-count  attempts [(3,3,60s),  (3,2,20s)]
  basic  : --offset <= rank < offset+basic attempts [(3,2,12s),  (3,1,4s)]
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ASSUMED_RATE = 60000  # keys/sec conservative floor for tries caps


def attempts_for(rank: int, strong: int, medium: int, offset: int, basic: int) -> list[tuple[int, int, int]]:
    if rank < strong:
        return [(4, 3, 150), (3, 3, 75), (3, 2, 25)]
    if rank < strong + medium:
        return [(3, 3, 45), (3, 2, 15)]
    if offset <= rank < offset + basic:
        return [(3, 2, 10), (3, 1, 3)]
    return []


def generate_one(binary: str, recipient: str, attempts: list[tuple[int, int, int]]) -> dict:
    rec = recipient.lower().replace("0x", "")
    total_tries = 0
    for p_len, s_len, seconds in attempts:
        prefix = rec[:p_len]
        suffix = rec[-s_len:]
        cap = int(seconds * ASSUMED_RATE)
        t0 = time.time()
        try:
            out = subprocess.run(
                [binary, "--prefix", prefix, "--suffix", suffix, "--max-tries", str(cap)],
                capture_output=True, text=True, timeout=seconds * 3 + 60,
            )
            data = json.loads(out.stdout.strip().splitlines()[-1]) if out.stdout.strip() else {"found": False, "tries": cap}
        except Exception:
            data = {"found": False, "tries": cap}
        total_tries += int(data.get("tries") or cap)
        if data.get("found"):
            return {
                "lookalike_address": data["address"],
                "lookalike_private_key": data["private_key"],
                "matched_prefix": p_len,
                "matched_suffix": s_len,
                "tries": total_tries,
                "seconds": round(time.time() - t0, 1),
            }
    return {"lookalike_address": "", "lookalike_private_key": "", "matched_prefix": 0, "matched_suffix": 0,
            "tries": total_tries, "seconds": 0.0}


def run(
    targets_csv: Path,
    out_csv: Path,
    binary: str,
    shard: int,
    num_shards: int,
    cores: int,
    strong: int,
    medium: int,
    offset: int,
    basic: int,
    progress_path: Path | None = None,
) -> None:
    tasks = []
    with open(targets_csv, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            rank = int(r["rank"])
            attempts = attempts_for(rank, strong, medium, offset, basic)
            if not attempts:
                continue
            tasks.append((rank, r["victim"], int(r["n_poisoning_events"]), int(r["recipient_rank"]), r["recipient"], attempts))
    tasks = [t for i, t in enumerate(tasks) if i % num_shards == shard]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    header = ["rank", "victim", "n_poisoning_events", "recipient_rank", "recipient",
              "lookalike_address", "lookalike_private_key", "matched_prefix", "matched_suffix", "tries", "seconds"]
    exists = out_csv.exists()
    fh = open(out_csv, "a", newline="", encoding="utf-8")
    w = csv.writer(fh)
    if not exists:
        w.writerow(header)
    fh.flush()

    done = 0

    def work(t):
        rank, victim, n, rr, recipient, attempts = t
        res = generate_one(binary, recipient, attempts)
        return rank, victim, n, rr, recipient, res

    with ThreadPoolExecutor(max_workers=cores) as ex:
        for rank, victim, n, rr, recipient, res in ex.map(work, tasks):
            w.writerow([rank, victim, n, rr, recipient, res["lookalike_address"], res["lookalike_private_key"],
                        res["matched_prefix"], res["matched_suffix"], res["tries"], res["seconds"]])
            fh.flush()
            done += 1
            if done % 25 == 0:
                print(f"shard {shard}: {done}/{len(tasks)} done", flush=True)
            if progress_path and done % 10 == 0:
                progress_path.write_text(
                    json.dumps({"shard": shard, "done": done, "total": len(tasks), "updated": int(time.time())})
                )
    fh.close()
    if progress_path:
        progress_path.write_text(
            json.dumps({"shard": shard, "done": done, "total": len(tasks), "updated": int(time.time())})
        )
    print(f"shard {shard}: finished {done} tasks -> {out_csv}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--targets", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--binary", default="./vanity")
    p.add_argument("--shard", type=int, required=True)
    p.add_argument("--num-shards", type=int, default=20)
    p.add_argument("--cores", type=int, default=4)
    p.add_argument("--strong-count", type=int, default=50)
    p.add_argument("--medium-count", type=int, default=2000)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--basic-count", type=int, default=10000)
    p.add_argument("--progress", type=Path, default=None)
    a = p.parse_args()
    run(a.targets, a.out, a.binary, a.shard, a.num_shards, a.cores, a.strong_count, a.medium_count, a.offset, a.basic_count, a.progress)


if __name__ == "__main__":
    main()
