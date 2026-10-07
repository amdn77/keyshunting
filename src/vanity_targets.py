"""Build the critical-victim target list for vanity lookalike generation.

Input : eoas_at_risk.csv (from the scan release)
Output: critical_targets.csv  columns: rank,victim,n_poisoning_events,recipient_rank,recipient
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path


def run(in_csv: Path, out_csv: Path, max_recipients: int = 5) -> None:
    rows = []
    with open(in_csv, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r.get("severity") != "critical":
                continue
            recs = [x for x in (r.get("frequent_recipients") or "").split(";") if x]
            if not recs:
                continue
            rows.append((int(r.get("n_poisoning_events") or 0), r["eoa"], recs[:max_recipients]))
    rows.sort(key=lambda t: -t[0])
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rank", "victim", "n_poisoning_events", "recipient_rank", "recipient"])
        rank = 0
        for n, victim, recs in rows:
            for i, rec in enumerate(recs):
                w.writerow([rank, victim, n, i, rec])
            rank += 1
    print(f"targets: {rank} victims, {sum(len(r[2]) for r in rows)} addresses -> {out_csv}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="in_csv", type=Path, required=True)
    p.add_argument("--out", dest="out_csv", type=Path, default=Path("critical_targets.csv"))
    p.add_argument("--max-recipients", type=int, default=5)
    a = p.parse_args()
    run(a.in_csv, a.out_csv, a.max_recipients)


if __name__ == "__main__":
    main()
