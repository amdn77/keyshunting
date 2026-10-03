# Keyshunting — EOA address-poisoning risk scanner on BNB Smart Chain

Goal: produce `eoas_at_risk.csv` — the set of EOAs whose transaction history shows evidence of
address-poisoning (tiny transfers, zero-value transfers, counterfeit-token transfers) together with the
frequent recipients they interact with and a severity tier (critical / high / low).

## Layout
- `src/rpc.py` — multi-endpoint JSON-RPC pool (BlockPI, NodeReal, public BSC seeds) with retry/failover.
- `src/blocks.py` — block-window fetch (full tx + receipt logs) into NDJSON shards.
- `src/detect.py` — poisoning detector implementing the lookalike (prefix ≥3, suffix ≥4 hex) heuristic
  plus tiny/zero-value/counterfeit-token transfer classification.
- `src/aggregate.py` — merges shard outputs into the final CSV with severity classification.
- `.github/workflows/scan.yml` — scheduled, sharded CI run that uploads per-shard artifacts and a final CSV.

## Local usage
```bash
pip install -r requirements.txt
cp .env.example .env   # fill in endpoints
python -m src.blocks --from-block N --to-block M --out shards/
python -m src.detect --in shards/ --out findings/
python -m src.aggregate --in findings/ --out eoas_at_risk.csv
```

## Methodology notes
Reference: "Blockchain Address Poisoning" (USENIX Security 2025). An EOA V is at risk when in its history
address L (attacker vanity address) closely mimics the legitimate counterparty R of V (same prefix ≥3 and
suffix ≥4 hex chars, case-insensitive) and V received a tiny / zero-value / counterfeit transfer from L.
Severity: critical = payoff occurred or zero-value spoof of an authentic counterparty; high = repeated
tiny/zero transfers from lookalikes, multiple counterparties affected; low = single lookalike dust event.
