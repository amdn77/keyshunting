"""Merge vanity lookalike shard CSVs into a cumulative CSV (one best row per victim+recipient)."""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

FIELDS = ["rank", "victim", "n_poisoning_events", "recipient_rank", "recipient",
          "lookalike_address", "lookalike_private_key", "matched_prefix", "matched_suffix", "tries", "seconds"]


def strength(row: dict) -> tuple:
    return (int(row.get("matched_prefix") or 0) + int(row.get("matched_suffix") or 0), row.get("lookalike_address") != "")


def run(new_dir: Path, existing: Path | None, out_csv: Path) -> None:
    best: dict[tuple[str, str], dict] = {}
    files = sorted(new_dir.rglob("*_lookalikes*.csv")) + sorted(new_dir.rglob("lookalikes*.csv"))
    for f in files:
        if "critical_victims_lookalikes" in f.name:
            continue
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if not r.get("lookalike_address"):
                    continue
                key = (r["victim"], r["recipient"])
                if key not in best or strength(r) > strength(best[key]):
                    best[key] = r
    if existing and existing.exists():
        with open(existing, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                key = (r["victim"], r["recipient"])
                if key not in best or strength(r) > strength(best[key]):
                    best[key] = r
    rows = sorted(best.values(), key=lambda r: (int(r.get("rank") or 0), int(r.get("recipient_rank") or 0)))
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"merged {len(rows)} lookalike rows -> {out_csv}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--new", dest="new_dir", type=Path, required=True)
    p.add_argument("--existing", type=Path, default=None)
    p.add_argument("--out", type=Path, default=Path("critical_victims_lookalikes.csv"))
    a = p.parse_args()
    run(a.new_dir, a.existing, a.out)


if __name__ == "__main__":
    main()
