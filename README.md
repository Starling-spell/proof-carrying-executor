# ProofCarryingExecutor

Consensus execution firewall for AI agents. It anchors an owner's intent and an authenticated agent manifest, refetches both before every evaluation, binds a structured action by SHA-256, and issues a one-use authorization. Failed attempts remain immutable and retry within the same logical action. Only successful consumption advances the head and stores a receipt.

## Verify

```bash
genvm-lint check contracts/ProofCarryingExecutor.py
genvm-lint check contracts/DemoExecutionAdapter.py
pnpm test
pnpm deploy
pnpm proof-success
pnpm proof-recovery
pnpm proof-drift
pnpm proof-replay
```

The executor allowlists adapters per policy owner. The demo adapter accepts calls only from its configured executor and independently rejects duplicate authorization IDs.

