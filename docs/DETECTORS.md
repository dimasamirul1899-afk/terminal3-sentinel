# Sentinel detectors

Sentinel is deterministic and rule-based. Every finding cites the exact
pattern that fired, so a human can verify it in seconds. There is no
probabilistic model and no external service — the same input always produces
the same report.

## Severity weights and verdict

| Severity | Weight | Meaning |
|----------|--------|---------|
| critical | 40 | Do not execute. Rug-pull / total-loss primitive. |
| high | 25 | Likely exploitable or a governance red flag. |
| medium | 10 | Real risk, needs a decision and usually a fix. |
| low | 3 | Hygiene / best practice. |
| info | 0 | Context, not a risk. |

Score starts at 100 and subtracts weights (floored at 0). Any critical finding
forces **REJECT**. Otherwise: score ≥ 80 → **APPROVE**, 50–79 → **REVIEW**,
< 50 → **REJECT**.

## Code detectors (`src/core.mjs`)

| ID | Severity | What it looks for |
|----|----------|-------------------|
| REENTRANCY | high | External call (`.call{value:}`, `.call(`, `.transfer`, `.send`) followed by a write to contract state in the same function (checks-effects-interactions violation). |
| UNCHECKED_CALL | high | Bare low-level `.call(`/`.call{value:}` whose boolean return is neither assigned nor wrapped in `require()`. |
| TX_ORIGIN | high | Any use of `tx.origin` for authorization. |
| DELEGATECALL | high | Any `.delegatecall(` — foreign code runs in this contract's storage context. |
| SELFDESTRUCT | critical | `selfdestruct(` / `suicide(` — the contract can be destroyed and its balance force-sent anywhere. |
| UNPROTECTED_UPGRADE | critical | An `upgradeTo` / `upgradeToAndCall` entry point (or wrapper) with no `onlyOwner` / `onlyAdmin` / `onlyRole` / sender check. |
| MISSING_ACCESS_CONTROL | high | A config-changing function (`set*`, `upgrade*`, `pause*`, `drain`, `sweep`, `rescue`, `execute`, `grant`, `revoke`, `burn`) or a payout function (`mint`, `transfer`, `transferFrom`) that pays an arbitrary address, with no access control. Self-service `withdraw`/`claim` (msg.sender only) is intentionally NOT flagged. |
| UNBOUNDED_LOOP | medium | External call inside a `for` loop — gas griefing / DoS as the set grows. |
| TIMESTAMP_DEPENDENCE | low | Any use of `block.timestamp` in logic. |
| WEAK_RANDOMNESS | medium | `blockhash` / `block.prevrandao` / `block.difficulty` combined with `%` (modulo). |
| FLOATING_PRAGMA | low | `pragma solidity ^x.y.z` instead of a pinned version. |
| ZERO_ADDRESS_CHECK | low | An address parameter stored into state without a `!= address(0)` check in the same function. |
| UNCAPPED_MINT | medium | A `mint` entry point with no supply-cap check (`totalSupply`, `MAX_SUPPLY`, `cap`). |
| PLAINTEXT_PII | medium | Personal-data identifiers (`email`, `phoneNumber`, `passport`, `ipAddress`, `fullName`, `dateOfBirth`) stored in contract state in plaintext. |

## Governance checks

| ID | Severity | Rule |
|----|----------|------|
| TREASURY_DRAIN | high | Requested amount > 25% of the treasury. |
| LARGE_TREASURY_SPEND | medium | Requested amount > 10% of the treasury. |
| NO_TIMELOCK | medium | `timelockSeconds == 0` — executes immediately. |
| SINGLE_SIGNER_EXECUTOR | medium | Executor is a single EOA. |
| SMALL_MULTISIG | low | Multisig with fewer than 3 signers. |
| PROXY_UPGRADE | high | Any target upgrades a proxy implementation. |
| CLAIM_VS_CODE_MISMATCH | high | Proposal claims "no code changes" but ships non-empty calldata. |
| DIRECT_ETH_TO_EOA | medium | ETH sent directly to an externally-owned account. |
| VAGUE_DESCRIPTION | low | Description shorter than 80 characters. |
| NEW_PROPOSER | info | First proposal from this proposer. |

## Privacy checks

| ID | Severity | Rule |
|----|----------|------|
| USER_DATA_COLLECTION | high | Proposal collects user data but its description states neither user consent nor data minimisation (hashing, encryption, off-chain storage, anonymisation). |
| PLAINTEXT_PII | medium | (code detector above) personal data in plaintext on-chain storage. |

## Known limitations (honest)

- Regex-based static analysis, not a full Solidity parser: it can miss
  vulnerabilities hidden behind indirection, and it can flag patterns that
  turn out benign on closer inspection. That is why the verdict is
  APPROVE / REVIEW / REJECT — REVIEW means "a human must look", not "unsafe".
- It analyses the code *attached to the proposal*. If the proposal executes
  code that is not attached, Sentinel says so only indirectly (via
  CLAIM_VS_CODE_MISMATCH when the claim contradicts the payload).
- It does not fetch on-chain state (balances, code at an address). All inputs
  are supplied in the proposal JSON, which keeps the agent fully offline and
  deterministic.
