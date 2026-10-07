"""Merge per-shard findings + recipients into eoas_at_risk.csv with severity tiers.

Handles both legacy shard CSVs (findings*.csv / recipients*.csv) and the
streaming scanner output (<shard>_findings.csv / <shard>_recipients.csv).
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from fnmatch import fnmatch
from pathlib import Path

CRITICAL_ATTACKS = {"zero_value", "counterfeit_token"}
HIGH_ATTACKS = {"tiny_native", "tiny_token"}


def severity(rows: list[dict]) -> str:
    """Confidence tier: repeat attacks + multiple lookalikes = strongest evidence."""
    kinds = {r["attack"] for r in rows}
    n_attackers = len({r["lookalike"] for r in rows})
    n = len(rows)
    if n >= 10 or n_attackers >= 3 or (n >= 3 and len(kinds) >= 2):
        return "critical"
    if n >= 2 or n_attackers >= 2:
        return "high"
    return "low"


def _iter_csvs(in_dir: Path, kind: str, match: str | None = None):
    """kind is 'findings' or 'recipients'; matches both legacy and scanner names once."""
    seen: set[Path] = set()
    patterns = [f"*_{kind}.csv", f"{kind}*.csv"]
    for pat in patterns:
        for f in sorted(in_dir.rglob(pat)):
            if f in seen or f.name == "eoas_at_risk.csv":
                continue
            seen.add(f)
            if match and not fnmatch(f.name, match + f"*{kind}.csv"):
                continue
            yield f


def run(in_dir: Path, out_csv: Path, verify: bool = True, verify_limit: int = 500, match: str | None = None) -> None:
    findings: dict[str, list[dict]] = defaultdict(list)
    recipients: dict[str, list[str]] = defaultdict(list)
    rec_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for f in _iter_csvs(in_dir, "findings", match):
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("victim"):
                    findings[r["victim"]].append(r)
    for f in _iter_csvs(in_dir, "recipients", match):
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("eoa") and r.get("recipient"):
                    rec_counts[r["eoa"]][r["recipient"]] += int(r.get("count") or 0)

    rows = []
    eoa_map: dict[str, bool] = {}
    if verify:
        from .verify import are_eoas

        try:
            eoa_map = are_eoas(list(findings.keys()))
        except Exception:
            eoa_map = {}

    def is_eoa(addr: str) -> bool:
        return eoa_map.get(addr, True) is not False

    for victim, fr in findings.items():
        if verify and not is_eoa(victim):
            continue
        recs = [r for r, _ in sorted(rec_counts.get(victim, {}).items(), key=lambda kv: -kv[1])][:15]
        # side-by-side: strongest lookalike per counterparty
        side = defaultdict(set)
        for r in fr:
            side[r["counterparty"]].add(r["lookalike"])
        side_str = ";".join(f"{cp}->{','.join(sorted(ls))}" for cp, ls in list(side.items())[:5])
        rows.append(
            {
                "eoa": victim,
                "severity": severity(fr),
                "frequent_recipients": ";".join(recs),
                "n_poisoning_events": len(fr),
                "attack_types": ";".join(sorted({r["attack"] for r in fr})),
                "lookalikes": ";".join(sorted({r["lookalike"] for r in fr})),
                "counterparties_mimicked": side_str,
                "first_block": min((int(r["block"]) for r in fr if r.get("block")), default=0),
                "last_block": max((int(r["block"]) for r in fr if r.get("block")), default=0),
                "sample_tx_hashes": ";".join(sorted({r["tx_hash"] for r in fr if r.get("tx_hash")})[:5]),
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
    p.add_argument("--in", dest="in_dir", type=Path, default=Path("results"))
    p.add_argument("--out", dest="out_csv", type=Path, default=Path("eoas_at_risk.csv"))
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--match", default=None, help="shard name prefix filter, e.g. 2023s01")
    a = p.parse_args()
    run(a.in_dir, a.out_csv, verify=not a.no_verify, match=a.match)


if __name__ == "__main__":
    main()
