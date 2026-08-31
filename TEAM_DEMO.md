# ProofCarryingExecutor

## Problem
AI agents can generate actions, but there is no trust-minimized layer proving that an action still matches the owner's intent and the agent identity originally approved.

## Primitive
ProofCarryingExecutor creates consensus-authorized, one-time execution capabilities.

## Guarantees
- anchored owner intent
- anchored agent identity
- independent validator refetch
- retryable immutable attempts
- exact action binding
- stale-head protection
- replay protection
- immutable execution receipt

## Live Proofs
- Executor: https://explorer-studio.genlayer.com/address/0xb360c790f11Eb7B4455bC38936113ca7B5309058
- Executor deployment: https://explorer-studio.genlayer.com/tx/0x29f4e69c47db2e0c283df277118394da184bd77eee02576c47784bd88723aea9
- Adapter: https://explorer-studio.genlayer.com/address/0x67443F8eCf7c084B7336F5dE758e54Bcea658e00
- Adapter deployment: https://explorer-studio.genlayer.com/tx/0x1aa48ea2d355718f62e9e7a50789ad55840934969b46345e94061391d6fc72e9

## Why GenLayer
Semantic authorization requires validator consensus over nondeterministic information while final execution remains deterministic.
