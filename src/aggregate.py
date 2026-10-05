"""Merge per-shard findings + recipients into eoas_at_risk.csv with severity tiers."""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

CRITICAL_ATTACKS = {"zero_value", "counterfeit_token"}
HIGH_ATTACKS = {"tiny_native", "tiny_token"}


def severity(rows: list[dict]) -> str:
    kinds = {r["attack"] for r in rows}
    n_attackers = len({r["lookalike"] for r in rows})
    if kinds & CRITICAL_ATTACKS or n_attackers >= 3:
        return "critical"
    if len(rows) >= 2 or n_attackers >= 2:
        return "high"
    return "low"


def run(in_dir: Path, out_csv: Path) -> None:
    findings: dict[str, list[dict]] = defaultdict(list)
    recipients: dict[str, list[str]] = defaultdict(list)

    for f in sorted(in_dir.rglob("findings*.csv")):
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                findings[r["victim"]].append(r)
    for f in sorted(in_dir.rglob("recipients*.csv")):
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                recipients[r["eoa"]].append(r["recipient"])

    rows = []
    # EOA verification cache
    eoa_cache: dict[str, bool] = {}

    from .verify import is_eoa as _is_eoa

    def is_eoa(addr: str) -> bool:
        if addr in eoa_cache:
            return eoa_cache[addr]
        try:
            ok = _is_eoa(addr)
        except Exception:
            ok = False
        eoa_cache[addr] = bool(ok)
        return bool(ok)

    for victim, fr in findings.items():
        if not is_eoa(victim):
            continue
        recs = sorted(set(recipients.get(victim, [])))
        rows.append(
            {
                "eoa": victim,
                "severity": severity(fr),
                "frequent_recipients": ";".join(recs[:10]),
                "n_poisoning_events": len(fr),
                "attack_types": ";".join(sorted({r["attack"] for r in fr})),
                "lookalikes": ";".join(sorted({r["lookalike"] for r in fr})),
                "counterparties_mimicked": ";".join(sorted({r["counterparty"] for r in fr})),
                "first_block": min(int(r["block"]) for r in fr),
                "last_block": max(int(r["block"]) for r in fr),
                "sample_tx_hashes": ";".join(sorted({r["tx_hash"] for r in fr})[:5]),
            }
        )
    rows.sort(key=lambda r: ({"critical": 0, "high": 1, "low": 2}[r["severity"]], -r["n_poisoning_events"]))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "eoa",
                "severity",
                "frequent_recipients",
                "n_poisoning_events",
                "attack_types",
                "lookalikes",
                "counterparties_mimicked",
                "first_block",
                "last_block",
                "sample_tx_hashes",
            ],
        )
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {out_csv}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="in_dir", type=Path, default=Path("findings"))
    p.add_argument("--out", dest="out_csv", type=Path, default=Path("eoas_at_risk.csv"))
    a = p.parse_args()
    run(a.in_dir, a.out_csv)


if __name__ == "__main__":
    main()
