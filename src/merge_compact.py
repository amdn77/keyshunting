"""Merge per-shard compact at-risk CSVs (results/*_at_risk.csv) into the final eoas_at_risk.csv.

Each shard file contains one row per victim EOA. This merges across shards,
unions lookalikes/recipients/mimicked counterparties, re-tiers severity, and
verifies EOAs in batch.
"""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from fnmatch import fnmatch
from pathlib import Path

from .aggregate import severity


def split(s: str | None) -> list[str]:
    return [x for x in (s or "").split(";") if x]


def run(in_dir: Path, out_csv: Path, verify: bool = True) -> None:
    victims: dict[str, list[dict]] = defaultdict(list)
    for f in sorted(in_dir.rglob("*_at_risk.csv")):
        if f.name == "eoas_at_risk.csv":
            continue
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("eoa"):
                    victims[r["eoa"]].append(r)

    eoa_map: dict[str, bool] = {}
    if verify:
        from .verify import are_eoas

        try:
            eoa_map = are_eoas(list(victims.keys()))
        except Exception:
            eoa_map = {}

    rows = []
    dropped = 0
    unknown = 0
    for eoa, parts in victims.items():
        if verify:
            verdict = eoa_map.get(eoa, None)
            if verdict is False:
                dropped += 1
                continue
            if verdict is None:
                unknown += 1
        if not parts:
            continue
        n = sum(int(p.get("n_poisoning_events") or 0) for p in parts)
        lookalikes = sorted({x for p in parts for x in split(p.get("lookalikes"))})
        attack_types = sorted({x for p in parts for x in split(p.get("attack_types"))})
        recipients = []
        for p in parts:
            recipients.extend(split(p.get("frequent_recipients")))
        recipients = list(dict.fromkeys(recipients))[:15]
        mimicked = list(dict.fromkeys(x for p in parts for x in split(p.get("counterparties_mimicked"))))
        txs = list(dict.fromkeys(x for p in parts for x in split(p.get("sample_tx_hashes"))))[:5]
        synthetic_rows = [{"attack": a, "lookalike": l} for a in attack_types for l in lookalikes] or [
            {"attack": a, "lookalike": "?"} for a in attack_types
        ]
        rows.append(
            {
                "eoa": eoa,
                "severity": severity(synthetic_rows) if synthetic_rows else "low",
                "frequent_recipients": ";".join(recipients),
                "n_poisoning_events": n,
                "attack_types": ";".join(attack_types),
                "lookalikes": ";".join(lookalikes),
                "counterparties_mimicked": ";".join(mimicked[:5]),
                "first_block": min((int(p["first_block"]) for p in parts if p.get("first_block")), default=0),
                "last_block": max((int(p["last_block"]) for p in parts if p.get("last_block")), default=0),
                "sample_tx_hashes": ";".join(txs),
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
    print(f"merged {len(rows)} unique at-risk EOAs -> {out_csv} (contracts dropped: {dropped}, unknown-kept: {unknown})")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="in_dir", type=Path, default=Path("results"))
    p.add_argument("--out", dest="out_csv", type=Path, default=Path("eoas_at_risk.csv"))
    p.add_argument("--no-verify", action="store_true")
    a = p.parse_args()
    run(a.in_dir, a.out_csv, verify=not a.no_verify)


if __name__ == "__main__":
    main()
