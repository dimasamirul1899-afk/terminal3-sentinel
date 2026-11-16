# Sentinel — DAO Proposal Security Agent

**Terminal 3 Build+Scale Agent Micro Grant (DoraHacks)** · deadline **24 Dec 2026, 15:59 UTC**

An autonomous agent that audits DAO governance proposals **and the smart-contract code they execute** — before the vote. It answers one question: *does this proposal do what it claims, and is it safe to execute?*

- **Security** — 14 static-analysis detectors over the executed Solidity code: reentrancy, unchecked calls, `tx.origin`, `delegatecall`, `selfdestruct`, unprotected proxy upgrades, missing access control, uncapped mint, weak randomness, and more.
- **Governance** — treasury-drain %, timelock, single-signer executor, proxy upgrades, claim-vs-code mismatch, direct ETH to EOAs, proposer history.
- **Trust** — every finding cites its evidence (pattern + file + line) and a weighted 0–100 score produces a verdict: **APPROVE / REVIEW / REJECT**.
- **Privacy** — flags plaintext personal data stored on-chain and proposals that collect user data without stated consent or minimisation (Terminal 3's core theme: user data must be private by default).

Fully deterministic and rule-based: same input → same report, every time. **No API key, no wallet, no server, no network.** Node 20+ stdlib only; the browser demo runs the exact same code as the CLI (byte-identical copy, verified by test).

## Live demo

**https://dimasamirul1899-afk.github.io/terminal3-sentinel/docs/**

Runs 100% in the browser. Pick a fixture (malicious upgrade, risky grant, privacy-risk registry, safe diversification) or paste your own proposal JSON and press **Analyse proposal**. Copy the markdown report with one click.

## Quickstart

```bash
git clone https://github.com/dimasamirul1899-afk/terminal3-sentinel.git
cd terminal3-sentinel
npm test            # 33 tests, stdlib only
npm run demo        # analyse all four bundled fixtures
node src/cli.mjs analyze fixtures/malicious-upgrade.mjs
node src/cli.mjs analyze fixtures/safe-treasury-diversification.mjs
node src/cli.mjs analyze my-proposal.json --json   # JSON or .mjs module
npm start           # serve the demo locally at http://127.0.0.1:8123
```

Exit code: `0` for APPROVE/REVIEW, `1` for REJECT (CI-friendly).

## How the agent works

```
proposal JSON
  ├─ code[] ──────────────► 14 Solidity detectors (docs/DETECTORS.md)
  ├─ treasury / timelock / executor / targets ──► governance checks
  └─ collectsUserData / dataDescription ────────► privacy checks
        │
        ▼
  weighted score (100 − Σ severity weights, floored at 0)
        │
        ▼
  verdict: APPROVE ≥ 80 · REVIEW 50–79 · REJECT < 50 or any critical
        │
        ▼
  report (markdown / JSON) with evidence per finding
```

### Proposal JSON shape

```json
{
  "id": "prop-001",
  "title": "Diversify 5% of treasury into stETH",
  "description": "…",
  "proposerProposals": 4,
  "treasuryBalance": 1000000,
  "requestedAmount": 50000,
  "timelockSeconds": 172800,
  "executor": { "type": "timelock", "signers": 0 },
  "targets": [{ "to": "0x…", "value": 0, "calldata": "0x…", "description": "…", "toIsContract": true }],
  "claimsNoCodeChange": false,
  "collectsUserData": false,
  "dataDescription": "",
  "code": [{ "file": "Vault.sol", "source": "pragma solidity 0.8.24; …" }]
}
```

## Fixtures (expected verdicts)

| Fixture | Verdict | Score | Why |
|---------|---------|-------|-----|
| `malicious-upgrade` | REJECT | 0/100 | "Routine maintenance" that upgrades a proxy to code with `selfdestruct`, unprotected `upgradeTo`, reentrancy, `tx.origin` auth, `delegatecall` — and claims "no code changes". |
| `risky-grant` | REVIEW | 61/100 | 15% treasury grant, no timelock, 2-of-2 multisig, direct ETH to an EOA. Nothing fatal, but a human must look. |
| `privacy-risk` | REVIEW | 55/100 | Voter registry storing emails + phone numbers in plaintext on-chain, with no stated consent or minimisation. |
| `safe-treasury-diversification` | APPROVE | 100/100 | 5% treasury, 48h timelock, guarded code, zero findings. |

## Why this agent, why now

DAO proposals are the soft underbelly of on-chain governance: the description says "routine maintenance" while the payload upgrades a proxy to a selfdestructing implementation. Existing audit tools check code in isolation; governance tools check votes in isolation. Sentinel is the agent that reads **both** — what the proposal claims, what it executes, and what the code actually does — and produces a verdict a voter can act on in one screen. It fits Terminal 3's thesis directly: trust and privacy in user-data infrastructure must be *verifiable*, not promised.

## Tests

```bash
npm test   # 33 tests: 30 core (detectors, scoring, governance, fixtures) + 3 demo parity
```

Demo parity tests guarantee `docs/core.mjs` is byte-identical to `src/core.mjs` and that the browser demo produces the same verdicts as the CLI. Regenerate the demo with `npm run build` after changing `src/` or `fixtures/`.

## Demo video script (2–3 min, for the submission)

> **0:00–0:15 — The problem.** "A DAO proposal says 'routine maintenance, no code changes'. The payload upgrades a proxy to a contract that can selfdestruct. Voters can't see that — unless an agent reads the code for them."
>
> **0:15–0:45 — The agent.** Show the demo page. Click the *Malicious upgrade* fixture, press Analyse. "Sentinel runs 14 code detectors plus governance and privacy checks — reentrancy, delegatecall, selfdestruct, unprotected upgrades — and scores the proposal 0 to 100."
>
> **0:45–1:20 — The verdict.** Scroll the findings: "Two criticals — selfdestruct and an unprotected upgrade — plus a claim-vs-code mismatch: it says no code changes but ships calldata. Verdict: REJECT. Do not execute."
>
> **1:20–2:00 — The middle ground.** Click *Risky grant*: "15% of the treasury, no timelock, 2-of-2 multisig — nothing fatal, but Sentinel says REVIEW, 61 out of 100. A human must look." Click *Privacy-risk registry*: "Emails and phone numbers stored in plaintext on-chain. Sentinel flags the privacy violation — user data must be private by default."
>
> **2:00–2:30 — The clean case + how it works.** Click *Safe diversification*: "100 out of 100, zero findings, APPROVE." Show the CLI: `node src/cli.mjs analyze …` and `npm test` — 33 tests passing. "Same code in the CLI, the tests, and the browser. No API key, no server, no wallet."
>
> **2:30–2:45 — Close.** "Sentinel: the agent that reads what a proposal really does, before the vote. Repo and demo in the description."

## Submission steps (for Bung Asta)

1. Create a DoraHacks account at https://dorahacks.io (if you don't have one).
2. Open the **Terminal 3 Build+Scale Agent Micro Grant** hackathon page on DoraHacks (search "Terminal 3" on dorahacks.io — the program is listed in the official DoraHacks November 2026 newsletter).
3. Submit before **24 Dec 2026, 15:59 UTC** with:
   - Repo: https://github.com/dimasamirul1899-afk/terminal3-sentinel
   - Live demo: https://dimasamirul1899-afk.github.io/terminal3-sentinel/docs/
   - Demo video (2–3 min, script above) — record and upload to YouTube, then paste the link.
4. No entry fee, no API key, no real money was used to build this.

## Honest notes

- The exact DoraHacks detail-page URL for this micro grant was not indexed in search at build time; the program's existence is confirmed via the official DoraHacks November 2026 newsletter (Nov 10 & Nov 16 editions, tags: Rust · WASM · Javascript). Prize ($1,800 top-2 pool) and deadline (24 Dec 2026 15:59 UTC) are from the program listing — please re-confirm both on the DoraHacks page before submitting.
- Detectors are regex-based static analysis, not a full Solidity parser: they can miss vulnerabilities hidden behind indirection and can flag patterns that turn out benign. That is why the output is a verdict with evidence, not a proof — see `docs/DETECTORS.md` for the full limitation list.
- The agent is written in JavaScript (Node stdlib, zero dependencies) rather than Rust/WASM: the grant's tags list Rust · WASM · Javascript, and the deliverable is a working agent — JavaScript is the fastest path to a verified, demoable agent with no paid toolchain. A Rust/WASM port of the detector core is a natural follow-up (the core is a single pure module, `src/core.mjs`, with no platform APIs).

## License

MIT — see [LICENSE](LICENSE).
