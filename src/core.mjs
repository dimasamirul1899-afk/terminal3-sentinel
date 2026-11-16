// Sentinel — DAO proposal security agent (Terminal 3 Build+Scale Agent Micro Grant)
// Platform-agnostic core: no Node APIs, so this exact file runs in the CLI,
// in node:test, and in the browser demo (docs/core.mjs is a byte-identical copy).
//
// Pipeline: parse proposal -> static analysis of the executed contract code
// -> governance risk checks -> privacy checks -> weighted score -> verdict.
//
// Verdicts: APPROVE (score >= 80, no critical finding)
//           REVIEW  (50-79, no critical finding)
//           REJECT  (< 50, or any critical finding)

export const SEVERITY_WEIGHT = { critical: 40, high: 25, medium: 10, low: 3, info: 0 };

export function scoreFindings(findings) {
  let score = 100;
  for (const f of findings) score -= SEVERITY_WEIGHT[f.severity] ?? 0;
  return Math.max(0, score);
}

export function verdictFor(findings) {
  if (findings.some((f) => f.severity === 'critical')) return 'REJECT';
  const score = scoreFindings(findings);
  if (score >= 80) return 'APPROVE';
  if (score >= 50) return 'REVIEW';
  return 'REJECT';
}

// ---------------------------------------------------------------------------
// Source helpers
// ---------------------------------------------------------------------------

// Strip // and /* */ comments while preserving line breaks (so line numbers
// in evidence stay correct). Strings are left untouched on purpose: a
// detector that fires inside a string literal is a rare, acceptable miss
// compared to the complexity of a full Solidity lexer.
export function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/\/\/[^\n]*/g, '');
}

export function lineOf(source, index) {
  return source.slice(0, index).split('\n').length;
}

// Split a Solidity source into top-level functions with brace matching.
// Returns [{ name, params, modifiers, body, startLine }].
export function splitFunctions(source) {
  const clean = stripComments(source);
  const out = [];
  const re = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*([^{;]*)\{/g;
  let m;
  while ((m = re.exec(clean)) !== null) {
    const bodyStart = m.index + m[0].length - 1; // position of '{'
    let depth = 0;
    let i = bodyStart;
    for (; i < clean.length; i++) {
      if (clean[i] === '{') depth++;
      else if (clean[i] === '}') {
        depth--;
        if (depth === 0) break;
      }
    }
    out.push({
      name: m[1],
      params: m[2],
      modifiers: m[3],
      body: clean.slice(bodyStart + 1, i),
      bodyStartIndex: bodyStart + 1,
      startLine: lineOf(clean, m.index),
    });
  }
  return out;
}

function finding(id, category, severity, title, detail, evidence, line) {
  return { id, category, severity, title, detail, evidence, line: line ?? null };
}

// ---------------------------------------------------------------------------
// Solidity static-analysis detectors. Each takes (source, file) and returns
// findings. All patterns are documented in docs/DETECTORS.md.
// ---------------------------------------------------------------------------

const EXTERNAL_CALL = /\.(call\s*\{value|\.call\s*\(|transfer\s*\(|send\s*\()/;

export function detectReentrancy(source, file) {
  const findings = [];
  for (const fn of splitFunctions(source)) {
    const callMatch = fn.body.match(/\.(call\s*\{value[^}]*\}|\.call\s*\(|transfer\s*\(|send\s*\()/);
    if (!callMatch) continue;
    const after = fn.body.slice(callMatch.index + callMatch[0].length);
    // A state write after the external call: `balances[x] -= ...`, `x = ...`,
    // `x += ...`, `delete x`. Local declarations (`uint x = ...`) are excluded
    // by requiring the assignment target to look like a storage slot, not a
    // fresh declaration.
    const write = after.match(
      /(?:^|;|\n)\s*(?:balances|_balances|totalSupply|claimed|spent|paid|owner|supply|state|locked|withdrawn|deposited|amounts|shares)\b[^;{]*?(?:\+=|-=|=(?!=))/m,
    );
    if (write) {
      findings.push(
        finding(
          'REENTRANCY',
          'security',
          'high',
          'Reentrancy: state updated after an external call',
          `Function ${fn.name}() makes an external call and only afterwards writes ` +
            `to contract state. An attacker contract can re-enter before the write ` +
            `lands and drain funds (classic DAO / checks-effects-interactions violation).`,
          `function ${fn.name}(...) { ... ${callMatch[0].trim()} ... ${write[0].trim().slice(0, 60)} ... }`,
          fn.startLine,
        ),
      );
    }
  }
  return findings;
}

export function detectUncheckedCall(source, file) {
  const findings = [];
  for (const fn of splitFunctions(source)) {
    // Bare low-level call whose return value is neither assigned nor wrapped
    // in require(): a line that starts a call without `=` before `.call(` or
    // `.call{value: ...}(...)`.
    for (const line of fn.body.split('\n')) {
      const t = line.trim();
      if (!t || t.startsWith('//')) continue;
      if (
        /\.call\s*(\{|\()/.test(t) &&
        !/require\s*\(/.test(t) &&
        !/=\s*[^=]*\.call\s*(\{|\()/.test(t) &&
        !/^\(/.test(t)
      ) {
        findings.push(
          finding(
            'UNCHECKED_CALL',
            'security',
            'high',
            'Unchecked low-level call return value',
            `Function ${fn.name}() ignores the boolean returned by a low-level ` +
              `.call(). A failed call is silently treated as success, so ETH can ` +
              `be "sent" without ever arriving.`,
            t.slice(0, 120),
            fn.startLine,
          ),
        );
        break; // one finding per function is enough
      }
    }
  }
  return findings;
}

export function detectTxOrigin(source, file) {
  const findings = [];
  const idx = source.indexOf('tx.origin');
  if (idx !== -1) {
    findings.push(
      finding(
        'TX_ORIGIN',
        'security',
        'high',
        'tx.origin used for authorization',
        `tx.origin authenticates the original transaction sender, not the direct ` +
          `caller. Any contract the owner interacts with can impersonate them. ` +
          `Use msg.sender instead.`,
        source.slice(Math.max(0, idx - 40), idx + 40).trim(),
        lineOf(source, idx),
      ),
    );
  }
  return findings;
}

export function detectDelegatecall(source, file) {
  const findings = [];
  const re = /\.delegatecall\s*\(/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    findings.push(
      finding(
        'DELEGATECALL',
        'security',
        'high',
        'delegatecall to a target address',
        `delegatecall executes foreign code in this contract's storage context. ` +
          `If the target is ever attacker-controlled, the whole contract (funds, ` +
          `ownership, implementation) is compromised.`,
        source.slice(Math.max(0, m.index - 40), m.index + 40).trim(),
        lineOf(source, m.index),
      ),
    );
  }
  return findings;
}

export function detectSelfdestruct(source, file) {
  const findings = [];
  const re = /\b(selfdestruct|suicide)\s*\(/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    findings.push(
      finding(
        'SELFDESTRUCT',
        'security',
        'critical',
        'Contract can be destroyed (selfdestruct)',
        `selfdestruct permanently deletes the contract and force-sends its ` +
          `balance to a chosen address. Hidden in a proposal payload, it is the ` +
          `classic rug-pull primitive: upgrade, drain, destroy.`,
        source.slice(Math.max(0, m.index - 40), m.index + 50).trim(),
        lineOf(source, m.index),
      ),
    );
  }
  return findings;
}

export function detectUnprotectedUpgrade(source, file) {
  const findings = [];
  for (const fn of splitFunctions(source)) {
    // The upgrade entry point is usually the function itself (upgradeTo), or
    // a wrapper that calls it — check both the name and the body.
    const isUpgrade =
      fn.name === 'upgradeTo' ||
      fn.name === 'upgradeToAndCall' ||
      /upgradeTo\s*\(/.test(fn.body) ||
      /upgradeToAndCall\s*\(/.test(fn.body);
    if (!isUpgrade) continue;
    const guarded =
      /onlyOwner|onlyAdmin|onlyRole|onlyGovernance|require\s*\(\s*msg\.sender\s*==/.test(fn.modifiers + fn.body);
    if (!guarded) {
      findings.push(
        finding(
          'UNPROTECTED_UPGRADE',
          'security',
          'critical',
          'Proxy upgrade with no access control',
          `Function ${fn.name}() can replace the implementation contract and has ` +
            `no owner/admin/role check. Anyone can point the proxy at malicious code.`,
          `function ${fn.name}(...) ${fn.modifiers.trim().slice(0, 60)}`,
          fn.startLine,
        ),
      );
    }
  }
  return findings;
}

// Only functions that can move funds to an arbitrary address or change
// global configuration are flagged. Self-service functions (withdraw/claim)
// that only ever pay msg.sender their own balance are the standard pattern
// and are NOT flagged — flagging them would be a false positive.
const CONFIG_VERBS = /^(set|upgrade|pause|unpause|drain|sweep|rescue|execute|grant|revoke|burn)/i;
const PAYOUT_VERBS = /^(mint|transfer|transferFrom)/i;

export function detectMissingAccessControl(source, file) {
  const findings = [];
  for (const fn of splitFunctions(source)) {
    const isConfig = CONFIG_VERBS.test(fn.name);
    const isPayout = PAYOUT_VERBS.test(fn.name);
    if (!isConfig && !isPayout) continue;
    // Payout functions are only dangerous when they can pay an arbitrary
    // address (an address parameter); paying msg.sender only is self-service.
    if (isPayout && !/address\s+(?:payable\s+)?[A-Za-z_$][\w$]*/.test(fn.params)) continue;
    if (/\b(view|pure)\b/.test(fn.modifiers)) continue;
    const guarded =
      /onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyMinter|require\s*\(\s*msg\.sender\s*==/.test(
        fn.modifiers + fn.body,
      );
    if (!guarded) {
      findings.push(
        finding(
          'MISSING_ACCESS_CONTROL',
          'security',
          'high',
          `Sensitive function ${fn.name}() has no access control`,
          `Function ${fn.name}() changes state (funds, ownership or configuration) ` +
            `and is callable by any address.`,
          `function ${fn.name}(${fn.params}) ${fn.modifiers.trim().slice(0, 80)}`,
          fn.startLine,
        ),
      );
    }
  }
  return findings;
}

export function detectUnboundedLoop(source, file) {
  const findings = [];
  for (const fn of splitFunctions(source)) {
    if (!/\bfor\s*\(/.test(fn.body)) continue;
    if (!EXTERNAL_CALL.test(fn.body)) continue;
    findings.push(
      finding(
        'UNBOUNDED_LOOP',
        'security',
        'medium',
        'External call inside a loop over a dynamic set',
        `Function ${fn.name}() makes external calls inside a loop. If the set ` +
          `grows, the transaction can run out of gas and brick the function ` +
          `(denial of service), or a single failing callee can block everyone.`,
        `function ${fn.name}(...) { ... for (...) { ... .call / .transfer ... } }`,
        fn.startLine,
      ),
    );
  }
  return findings;
}

export function detectTimestampDependence(source, file) {
  const findings = [];
  const re = /block\.timestamp/g;
  let m;
  let count = 0;
  while ((m = re.exec(source)) !== null) count++;
  if (count > 0) {
    findings.push(
      finding(
        'TIMESTAMP_DEPENDENCE',
        'security',
        'low',
        'Logic depends on block.timestamp',
        `block.timestamp appears ${count} time(s). Miners/validators can skew it ` +
          `by ~15 seconds, so it must never decide money or randomness.`,
        source.slice(source.indexOf('block.timestamp') - 30, source.indexOf('block.timestamp') + 40).trim(),
        lineOf(source, source.indexOf('block.timestamp')),
      ),
    );
  }
  return findings;
}

export function detectWeakRandomness(source, file) {
  const findings = [];
  if (/(blockhash|block\.prevrandao|block\.difficulty)\s*\(/.test(source) && /%/.test(source)) {
    const idx = source.search(/blockhash|block\.prevrandao|block\.difficulty/);
    findings.push(
      finding(
        'WEAK_RANDOMNESS',
        'security',
        'medium',
        'Weak on-chain randomness',
        `Randomness derived from block data is predictable and manipulable by ` +
          `validators. Use a VRF oracle for anything that pays out.`,
        source.slice(Math.max(0, idx - 30), idx + 60).trim(),
        lineOf(source, idx),
      ),
    );
  }
  return findings;
}

export function detectFloatingPragma(source, file) {
  const findings = [];
  const m = source.match(/pragma\s+solidity\s+\^[\d.]+/);
  if (m) {
    findings.push(
      finding(
        'FLOATING_PRAGMA',
        'security',
        'low',
        'Floating compiler pragma',
        `A floating pragma (^) lets the contract compile with any newer compiler ` +
          `version, including ones with different behaviour. Pin an exact version.`,
        m[0],
        lineOf(source, m.index),
      ),
    );
  }
  return findings;
}

export function detectZeroAddressCheck(source, file) {
  const findings = [];
  for (const fn of splitFunctions(source)) {
    const addrParams = [...fn.params.matchAll(/address\s+(?:payable\s+)?([A-Za-z_$][\w$]*)/g)].map((x) => x[1]);
    if (addrParams.length === 0) continue;
    const assignsState = addrParams.some((p) => new RegExp(`\\b\\w+\\s*=\\s*${p}\\b`).test(fn.body));
    if (!assignsState) continue;
    const checked = addrParams.some((p) => new RegExp(`${p}\\s*!=\\s*address\\(0\\)`).test(fn.body));
    if (!checked) {
      findings.push(
        finding(
          'ZERO_ADDRESS_CHECK',
          'security',
          'low',
          `Address parameter stored without a zero-address check`,
          `Function ${fn.name}() stores an address parameter (${addrParams.join(', ')}) ` +
            `into state without checking it against address(0). A typo can burn ` +
            `the role or the funds.`,
          `function ${fn.name}(${fn.params})`,
          fn.startLine,
        ),
      );
    }
  }
  return findings;
}

export function detectCentralizedMint(source, file) {
  const findings = [];
  for (const fn of splitFunctions(source)) {
    // The mint entry point is usually the function itself (mint), or a wrapper
    // that calls an internal _mint — check both the name and the body.
    if (fn.name !== 'mint' && !/\bmint\s*\(/.test(fn.body)) continue;
    const hasCap = /require\s*\([^)]*totalSupply|MAX_SUPPLY|cap/i.test(fn.body);
    if (!hasCap) {
      findings.push(
        finding(
          'UNCAPPED_MINT',
          'security',
          'medium',
          'Mint function has no supply cap',
          `Function ${fn.name}() can mint new tokens with no cap check. A ` +
            `compromised owner key (or a malicious proposal) can inflate the ` +
            `supply to zero value.`,
          `function ${fn.name}(...) { ... mint(...) ... }`,
          fn.startLine,
        ),
      );
    }
  }
  return findings;
}

// Privacy detectors: plaintext personal data held in contract storage.
export function detectPlaintextPII(source, file) {
  const findings = [];
  const re = /\b(email|ipAddress|ip_address|passport|phoneNumber|phone_number|fullName|dateOfBirth)\b/g;
  let m;
  const seen = new Set();
  while ((m = re.exec(source)) !== null) {
    if (seen.has(m[1])) continue;
    seen.add(m[1]);
    findings.push(
      finding(
        'PLAINTEXT_PII',
        'privacy',
        'medium',
        `Personal data stored in plaintext on-chain: ${m[1]}`,
        `On-chain storage is public forever. Storing ${m[1]} in plaintext ` +
          `exposes users permanently and conflicts with data-minimisation ` +
          `principles (Terminal 3's core theme). Hash it, encrypt it, or keep it off-chain.`,
        source.slice(Math.max(0, m.index - 30), m.index + 50).trim(),
        lineOf(source, m.index),
      ),
    );
  }
  return findings;
}

export const CODE_DETECTORS = [
  detectReentrancy,
  detectUncheckedCall,
  detectTxOrigin,
  detectDelegatecall,
  detectSelfdestruct,
  detectUnprotectedUpgrade,
  detectMissingAccessControl,
  detectUnboundedLoop,
  detectTimestampDependence,
  detectWeakRandomness,
  detectFloatingPragma,
  detectZeroAddressCheck,
  detectCentralizedMint,
  detectPlaintextPII,
];

export function analyzeCode(codeFiles) {
  const findings = [];
  for (const { file, source } of codeFiles ?? []) {
    for (const detector of CODE_DETECTORS) {
      for (const f of detector(source, file)) {
        findings.push({ ...f, file: file ?? null });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Governance checks (proposal-level)
// ---------------------------------------------------------------------------

export function analyzeGovernance(p) {
  const findings = [];
  const treasury = p.treasuryBalance ?? 0;
  const requested = p.requestedAmount ?? 0;

  if (treasury > 0 && requested > 0) {
    const ratio = requested / treasury;
    if (ratio > 0.25) {
      findings.push(
        finding(
          'TREASURY_DRAIN',
          'governance',
          'high',
          `Proposal spends ${(ratio * 100).toFixed(1)}% of the treasury in one go`,
          `Requested ${requested} of a ${treasury} treasury. A single proposal ` +
            `moving more than a quarter of the treasury is a concentration risk ` +
            `even when the destination looks legitimate.`,
          `requestedAmount=${requested}, treasuryBalance=${treasury}`,
        ),
      );
    } else if (ratio > 0.1) {
      findings.push(
        finding(
          'LARGE_TREASURY_SPEND',
          'governance',
          'medium',
          `Proposal spends ${(ratio * 100).toFixed(1)}% of the treasury`,
          `Above the 10% threshold where large spends normally require staged ` +
            `releases or milestone-based payouts.`,
          `requestedAmount=${requested}, treasuryBalance=${treasury}`,
        ),
      );
    }
  }

  if ((p.timelockSeconds ?? 0) === 0) {
    findings.push(
      finding(
        'NO_TIMELOCK',
        'governance',
        'medium',
        'Proposal executes immediately — no timelock',
        `With no execution delay, token holders cannot exit or veto before the ` +
          `payload runs. Standard practice is 24-48h.`,
        'timelockSeconds=0',
      ),
    );
  }

  if (p.executor?.type === 'eoa') {
    findings.push(
      finding(
        'SINGLE_SIGNER_EXECUTOR',
        'governance',
        'medium',
        'Execution controlled by a single externally-owned account',
        `The executor is a single EOA. One compromised key executes the whole ` +
          `payload. Use a multisig or the DAO timelock contract.`,
        `executor.type=eoa`,
      ),
    );
  } else if (p.executor?.type === 'multisig' && (p.executor.signers ?? 0) < 3) {
    findings.push(
      finding(
        'SMALL_MULTISIG',
        'governance',
        'low',
        'Multisig has fewer than 3 signers',
        `A 2-of-2 multisig is barely better than a single key: one lost key ` +
          `bricks execution, one compromised key plus one mistake drains it.`,
        `executor.signers=${p.executor.signers}`,
      ),
    );
  }

  const targets = p.targets ?? [];
  const hasUpgrade = targets.some(
    (t) => /upgrade/i.test(t.description ?? '') || /upgradeTo/.test(t.calldata ?? ''),
  );
  if (hasUpgrade) {
    findings.push(
      finding(
        'PROXY_UPGRADE',
        'governance',
        'high',
        'Proposal upgrades a proxy implementation',
        `Implementation upgrades replace all logic of a live contract. They ` +
          `deserve the highest scrutiny: the new code must be audited and its ` +
          `diff reviewed line by line.`,
        targets
          .filter((t) => /upgrade/i.test(t.description ?? '') || /upgradeTo/.test(t.calldata ?? ''))
          .map((t) => t.to)
          .join(', '),
      ),
    );
  }

  if (p.claimsNoCodeChange && targets.some((t) => (t.calldata ?? '') && t.calldata !== '0x')) {
    findings.push(
      finding(
        'CLAIM_VS_CODE_MISMATCH',
        'governance',
        'high',
        'Proposal claims "no code changes" but ships calldata',
        `The description says no code changes, yet the payload contains ` +
          `non-empty calldata. What a proposal says and what it does must match ` +
          `exactly — a mismatch is the signature of a disguised payload.`,
        `targets with calldata: ${targets.filter((t) => (t.calldata ?? '') && t.calldata !== '0x').length}`,
      ),
    );
  }

  const directEthToEoa = targets.filter((t) => (t.value ?? 0) > 0 && t.toIsContract === false);
  if (directEthToEoa.length > 0) {
    findings.push(
      finding(
        'DIRECT_ETH_TO_EOA',
        'governance',
        'medium',
        'Direct ETH transfer to an externally-owned account',
        `${directEthToEoa.length} target(s) send ETH straight to an EOA with no ` +
          `contract logic in between. Funds leave DAO control with no ` +
          `enforceable conditions.`,
        directEthToEoa.map((t) => `${t.to} (${t.value})`).join(', '),
      ),
    );
  }

  if ((p.description ?? '').trim().length < 80) {
    findings.push(
      finding(
        'VAGUE_DESCRIPTION',
        'governance',
        'low',
        'Proposal description is too short to review',
        `A ${String(p.description ?? '').trim().length}-character description cannot ` +
          `explain what the payload does, why it is needed, or what the risks are.`,
        `description length=${String(p.description ?? '').trim().length}`,
      ),
    );
  }

  if ((p.proposerProposals ?? 0) === 0) {
    findings.push(
      finding(
        'NEW_PROPOSER',
        'governance',
        'info',
        'First proposal from this proposer',
        `No proposal history to judge this proposer by. Not a risk by itself, ` +
          `but it removes the reputation signal other checks rely on.`,
        'proposerProposals=0',
      ),
    );
  }

  if (p.collectsUserData) {
    const desc = (p.dataDescription ?? '').toLowerCase();
    const mentionsConsent = /consent|opt-?in|permission/.test(desc);
    const mentionsMinimisation = /minimi|hash|encrypt|off-?chain|anonymi/.test(desc);
    if (!mentionsConsent || !mentionsMinimisation) {
      findings.push(
        finding(
          'USER_DATA_COLLECTION',
          'privacy',
          'high',
          'Proposal collects user data without stated consent or minimisation',
          `The proposal collects user data but its description states neither ` +
            `user consent nor data minimisation (hashing, encryption, off-chain ` +
            `storage). User data infrastructure must be private by default.`,
          `dataDescription="${(p.dataDescription ?? '').slice(0, 100)}"`,
        ),
      );
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Agent pipeline
// ---------------------------------------------------------------------------

export function analyzeProposal(proposal) {
  const findings = [
    ...analyzeCode(proposal.code ?? []),
    ...analyzeGovernance(proposal),
  ];
  const score = scoreFindings(findings);
  const verdict = verdictFor(findings);
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  const byCategory = { security: 0, governance: 0, privacy: 0 };
  for (const f of findings) byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;

  const summary =
    verdict === 'APPROVE'
      ? `No critical issues. ${findings.length} finding(s), none blocking. Safe to execute as written.`
      : verdict === 'REVIEW'
        ? `${findings.length} finding(s) need human review before execution. Do not execute blindly.`
        : `${findings.length} finding(s) including ${bySeverity.critical} critical. Do NOT execute.`;

  return {
    proposalId: proposal.id ?? null,
    title: proposal.title ?? null,
    verdict,
    score,
    summary,
    counts: { total: findings.length, bySeverity, byCategory },
    findings: [...findings].sort(
      (a, b) =>
        (SEVERITY_WEIGHT[b.severity] ?? 0) - (SEVERITY_WEIGHT[a.severity] ?? 0),
    ),
  };
}

export function reportMarkdown(report) {
  const lines = [];
  lines.push(`# Sentinel report — ${report.title ?? report.proposalId ?? 'proposal'}`);
  lines.push('');
  lines.push(`**Verdict: ${report.verdict}** — risk score ${report.score}/100`);
  lines.push('');
  lines.push(report.summary);
  lines.push('');
  lines.push(
    `Findings: ${report.counts.total} ` +
      `(critical ${report.counts.bySeverity.critical}, high ${report.counts.bySeverity.high}, ` +
      `medium ${report.counts.bySeverity.medium}, low ${report.counts.bySeverity.low}, ` +
      `info ${report.counts.bySeverity.info})`,
  );
  lines.push('');
  for (const f of report.findings) {
    lines.push(`## [${f.severity.toUpperCase()}] ${f.title} (${f.id})`);
    lines.push(`Category: ${f.category}${f.file ? ` · file: ${f.file}` : ''}${f.line ? ` · line ${f.line}` : ''}`);
    lines.push('');
    lines.push(f.detail);
    if (f.evidence) {
      lines.push('');
      lines.push('```');
      lines.push(f.evidence);
      lines.push('```');
    }
    lines.push('');
  }
  return lines.join('\n');
}
