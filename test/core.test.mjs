// Sentinel core tests — node:test, stdlib only. No network, no fixtures on
// disk needed for the unit tests (Solidity snippets are inline).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeProposal,
  analyzeCode,
  analyzeGovernance,
  scoreFindings,
  verdictFor,
  reportMarkdown,
  stripComments,
  splitFunctions,
} from '../src/core.mjs';
import safeFixture from '../fixtures/safe-treasury-diversification.mjs';
import maliciousFixture from '../fixtures/malicious-upgrade.mjs';
import riskyFixture from '../fixtures/risky-grant.mjs';
import privacyFixture from '../fixtures/privacy-risk.mjs';

const ids = (findings) => findings.map((f) => f.id);

function code(source) {
  return [{ file: 'Test.sol', source }];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

test('stripComments removes comments but preserves line numbers', () => {
  const src = 'line1\n// comment\nline3\n/* multi\nline */\nline6';
  const clean = stripComments(src);
  assert.equal(clean.split('\n').length, src.split('\n').length);
  assert.ok(!clean.includes('comment'));
  assert.ok(!clean.includes('multi'));
  assert.ok(clean.includes('line1') && clean.includes('line6'));
});

test('splitFunctions extracts function names and bodies', () => {
  const src = 'contract A { function foo() public {} function bar(uint x) external onlyOwner {} }';
  const fns = splitFunctions(src);
  assert.deepEqual(fns.map((f) => f.name), ['foo', 'bar']);
  assert.ok(fns[1].modifiers.includes('onlyOwner'));
});

// ---------------------------------------------------------------------------
// Security detectors
// ---------------------------------------------------------------------------

test('reentrancy: call-then-write fires; checks-effects-interactions does not', () => {
  const vuln = `contract V {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
      (bool ok, ) = msg.sender.call{value: amount}("");
      require(ok);
      balances[msg.sender] = 0;
    }
  }`;
  const safe = `contract S {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
      balances[msg.sender] = 0;
      (bool ok, ) = msg.sender.call{value: amount}("");
      require(ok);
    }
  }`;
  assert.ok(ids(analyzeCode(code(vuln))).includes('REENTRANCY'));
  assert.ok(!ids(analyzeCode(code(safe))).includes('REENTRANCY'));
});

test('unchecked call: bare .call fires; assigned + require does not', () => {
  const vuln = 'contract V { function f(address t) public { t.call{value: 1 ether}(""); } }';
  const safe =
    'contract S { function f(address t) public { (bool ok, ) = t.call{value: 1 ether}(""); require(ok); } }';
  assert.ok(ids(analyzeCode(code(vuln))).includes('UNCHECKED_CALL'));
  assert.ok(!ids(analyzeCode(code(safe))).includes('UNCHECKED_CALL'));
});

test('tx.origin fires', () => {
  const src = 'contract V { address owner; function f() public { require(tx.origin == owner); } }';
  const f = analyzeCode(code(src)).find((x) => x.id === 'TX_ORIGIN');
  assert.ok(f && f.severity === 'high');
});

test('delegatecall fires', () => {
  const src = 'contract V { function f(bytes memory d) public { address(0x1).delegatecall(d); } }';
  assert.ok(ids(analyzeCode(code(src))).includes('DELEGATECALL'));
});

test('selfdestruct is critical', () => {
  const src = 'contract V { function kill() public { selfdestruct(payable(msg.sender)); } }';
  const f = analyzeCode(code(src)).find((x) => x.id === 'SELFDESTRUCT');
  assert.ok(f && f.severity === 'critical');
});

test('unprotected upgrade: unguarded is critical, onlyOwner is clean', () => {
  const vuln = 'contract V { address impl; function upgradeTo(address n) public { impl = n; } }';
  const safe =
    'contract S { address impl; function upgradeTo(address n) public onlyOwner { impl = n; } modifier onlyOwner() { require(msg.sender == owner); _; } address owner; }';
  const vf = analyzeCode(code(vuln)).find((x) => x.id === 'UNPROTECTED_UPGRADE');
  assert.ok(vf && vf.severity === 'critical');
  assert.ok(!ids(analyzeCode(code(safe))).includes('UNPROTECTED_UPGRADE'));
});

test('missing access control: unguarded mint(to) fires, guarded does not, self-service withdraw does not', () => {
  const vuln = 'contract V { function mint(address to, uint256 a) public { } }';
  const guarded =
    'contract S { function mint(address to, uint256 a) public onlyOwner { } modifier onlyOwner() { require(msg.sender == owner); _; } address owner; }';
  const selfService =
    'contract S { mapping(address => uint) public balances; function withdraw(uint a) public { balances[msg.sender] -= a; } }';
  assert.ok(ids(analyzeCode(code(vuln))).includes('MISSING_ACCESS_CONTROL'));
  assert.ok(!ids(analyzeCode(code(guarded))).includes('MISSING_ACCESS_CONTROL'));
  assert.ok(!ids(analyzeCode(code(selfService))).includes('MISSING_ACCESS_CONTROL'));
});

test('unbounded loop: external call in loop fires; pure loop does not', () => {
  const vuln =
    'contract V { address[] users; function pay() public { for (uint i = 0; i < users.length; i++) { users[i].transfer(1); } } }';
  const safe =
    'contract S { uint[] xs; function sum() public view returns (uint s) { for (uint i = 0; i < xs.length; i++) { s += xs[i]; } } }';
  assert.ok(ids(analyzeCode(code(vuln))).includes('UNBOUNDED_LOOP'));
  assert.ok(!ids(analyzeCode(code(safe))).includes('UNBOUNDED_LOOP'));
});

test('timestamp dependence is low', () => {
  const src = 'contract V { function f() public { require(block.timestamp > 100); } }';
  const f = analyzeCode(code(src)).find((x) => x.id === 'TIMESTAMP_DEPENDENCE');
  assert.ok(f && f.severity === 'low');
});

test('weak randomness: blockhash with modulo fires; without modulo does not', () => {
  const vuln = 'contract V { function roll() public view returns (uint) { return uint(blockhash(block.number - 1)) % 100; } }';
  const safe = 'contract S { function h() public view returns (bytes32) { return blockhash(block.number - 1); } }';
  assert.ok(ids(analyzeCode(code(vuln))).includes('WEAK_RANDOMNESS'));
  assert.ok(!ids(analyzeCode(code(safe))).includes('WEAK_RANDOMNESS'));
});

test('floating pragma fires; exact pragma does not', () => {
  assert.ok(ids(analyzeCode(code('pragma solidity ^0.8.0;'))).includes('FLOATING_PRAGMA'));
  assert.ok(!ids(analyzeCode(code('pragma solidity 0.8.24;'))).includes('FLOATING_PRAGMA'));
});

test('zero-address check: stored param without check fires; with check does not', () => {
  const vuln =
    'contract V { address v; function set(address n) public { v = n; } }';
  const safe =
    'contract S { address v; function set(address n) public { require(n != address(0)); v = n; } }';
  assert.ok(ids(analyzeCode(code(vuln))).includes('ZERO_ADDRESS_CHECK'));
  assert.ok(!ids(analyzeCode(code(safe))).includes('ZERO_ADDRESS_CHECK'));
});

test('uncapped mint fires; capped mint does not', () => {
  const vuln = 'contract V { uint total; function mint(address t, uint a) public { total += a; } }';
  const safe =
    'contract S { uint total; uint constant MAX_SUPPLY = 1000; function mint(address t, uint a) public { require(total + a <= MAX_SUPPLY); total += a; } }';
  assert.ok(ids(analyzeCode(code(vuln))).includes('UNCAPPED_MINT'));
  assert.ok(!ids(analyzeCode(code(safe))).includes('UNCAPPED_MINT'));
});

test('plaintext PII: email/phone fields fire; no PII does not', () => {
  const vuln = 'contract V { mapping(address => string) public email; string public phoneNumber; }';
  const f = analyzeCode(code(vuln)).filter((x) => x.id === 'PLAINTEXT_PII');
  assert.equal(f.length, 2);
  assert.ok(f.every((x) => x.category === 'privacy' && x.severity === 'medium'));
  assert.equal(analyzeCode(code('contract S { mapping(address => uint) public votes; }')).length, 0);
});

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

test('scoreFindings weights severities', () => {
  assert.equal(scoreFindings([]), 100);
  assert.equal(scoreFindings([{ severity: 'critical' }]), 60);
  assert.equal(scoreFindings([{ severity: 'high' }]), 75);
  assert.equal(scoreFindings([{ severity: 'medium' }]), 90);
  assert.equal(scoreFindings([{ severity: 'low' }]), 97);
  assert.equal(scoreFindings([{ severity: 'info' }]), 100);
  assert.equal(scoreFindings([{ severity: 'critical' }, { severity: 'critical' }, { severity: 'high' }]), 0);
});

test('verdict boundaries: 80 approve, 79 review, 50 review, 49 reject, critical rejects', () => {
  const mk = (n) => Array.from({ length: n }, () => ({ severity: 'low' })); // 3 pts each
  // 100 - 3*6 = 82 -> APPROVE ; 100 - 3*7 = 79 -> REVIEW
  assert.equal(verdictFor(mk(6)), 'APPROVE');
  assert.equal(verdictFor(mk(7)), 'REVIEW');
  // 100 - 10*5 = 50 -> REVIEW ; 100 - 10*5 - 3 = 47 -> REJECT
  const med = Array.from({ length: 5 }, () => ({ severity: 'medium' }));
  assert.equal(verdictFor(med), 'REVIEW');
  assert.equal(verdictFor([...med, { severity: 'low' }]), 'REJECT');
  assert.equal(verdictFor([{ severity: 'critical' }]), 'REJECT');
  assert.equal(verdictFor([]), 'APPROVE');
});

// ---------------------------------------------------------------------------
// Governance checks
// ---------------------------------------------------------------------------

const baseProposal = {
  id: 'p1',
  title: 'Test',
  description: 'A sufficiently long description that explains what this proposal does and why.',
  proposerProposals: 3,
  treasuryBalance: 1000000,
  requestedAmount: 0,
  timelockSeconds: 86400,
  executor: { type: 'timelock' },
  targets: [],
  claimsNoCodeChange: false,
  collectsUserData: false,
};

test('treasury: >25% is high, 15% is medium, 5% is clean', () => {
  assert.ok(ids(analyzeGovernance({ ...baseProposal, requestedAmount: 300000 })).includes('TREASURY_DRAIN'));
  assert.ok(ids(analyzeGovernance({ ...baseProposal, requestedAmount: 150000 })).includes('LARGE_TREASURY_SPEND'));
  assert.ok(!ids(analyzeGovernance({ ...baseProposal, requestedAmount: 50000 })).includes('TREASURY_DRAIN'));
  assert.ok(!ids(analyzeGovernance({ ...baseProposal, requestedAmount: 50000 })).includes('LARGE_TREASURY_SPEND'));
});

test('no timelock fires medium; timelock set is clean', () => {
  assert.ok(ids(analyzeGovernance({ ...baseProposal, timelockSeconds: 0 })).includes('NO_TIMELOCK'));
  assert.ok(!ids(analyzeGovernance(baseProposal)).includes('NO_TIMELOCK'));
});

test('executor: EOA is medium, 2-of-2 is low, timelock is clean', () => {
  assert.ok(
    ids(analyzeGovernance({ ...baseProposal, executor: { type: 'eoa' } })).includes('SINGLE_SIGNER_EXECUTOR'),
  );
  assert.ok(
    ids(analyzeGovernance({ ...baseProposal, executor: { type: 'multisig', signers: 2 } })).includes(
      'SMALL_MULTISIG',
    ),
  );
  assert.ok(
    !ids(analyzeGovernance({ ...baseProposal, executor: { type: 'multisig', signers: 3 } })).includes(
      'SMALL_MULTISIG',
    ),
  );
});

test('proxy upgrade and claim-vs-code mismatch fire high', () => {
  const upgrade = {
    ...baseProposal,
    targets: [{ to: '0x1', value: 0, calldata: '0x3659cfe6', description: 'Upgrade implementation', toIsContract: true }],
  };
  assert.ok(ids(analyzeGovernance(upgrade)).includes('PROXY_UPGRADE'));
  const mismatch = {
    ...baseProposal,
    claimsNoCodeChange: true,
    targets: [{ to: '0x1', value: 0, calldata: '0xdeadbeef', description: 'config', toIsContract: true }],
  };
  assert.ok(ids(analyzeGovernance(mismatch)).includes('CLAIM_VS_CODE_MISMATCH'));
  const honest = { ...mismatch, claimsNoCodeChange: false };
  assert.ok(!ids(analyzeGovernance(honest)).includes('CLAIM_VS_CODE_MISMATCH'));
});

test('direct ETH to EOA fires medium; to contract does not', () => {
  const eoa = {
    ...baseProposal,
    targets: [{ to: '0xabc', value: 100, calldata: '0x', description: 'pay', toIsContract: false }],
  };
  assert.ok(ids(analyzeGovernance(eoa)).includes('DIRECT_ETH_TO_EOA'));
  const contract = { ...eoa, targets: [{ ...eoa.targets[0], toIsContract: true }] };
  assert.ok(!ids(analyzeGovernance(contract)).includes('DIRECT_ETH_TO_EOA'));
});

test('vague description fires low; new proposer is info only', () => {
  assert.ok(ids(analyzeGovernance({ ...baseProposal, description: 'do it' })).includes('VAGUE_DESCRIPTION'));
  const f = analyzeGovernance({ ...baseProposal, proposerProposals: 0 }).find((x) => x.id === 'NEW_PROPOSER');
  assert.ok(f && f.severity === 'info');
});

test('user data collection: no consent/minimisation fires high; consent + hashing is clean', () => {
  const bad = {
    ...baseProposal,
    collectsUserData: true,
    dataDescription: 'Store voter email and phone for marketing',
  };
  const f = analyzeGovernance(bad).find((x) => x.id === 'USER_DATA_COLLECTION');
  assert.ok(f && f.severity === 'high');
  const good = {
    ...baseProposal,
    collectsUserData: true,
    dataDescription: 'Collect wallet addresses with opt-in consent; hashed before storage.',
  };
  assert.ok(!ids(analyzeGovernance(good)).includes('USER_DATA_COLLECTION'));
});

// ---------------------------------------------------------------------------
// End to end on the bundled fixtures
// ---------------------------------------------------------------------------

test('safe fixture approves with score 100 and zero findings', () => {
  const r = analyzeProposal(safeFixture);
  assert.equal(r.verdict, 'APPROVE');
  assert.equal(r.score, 100);
  assert.equal(r.counts.total, 0);
});

test('malicious fixture rejects with critical SELFDESTRUCT + UNPROTECTED_UPGRADE', () => {
  const r = analyzeProposal(maliciousFixture);
  assert.equal(r.verdict, 'REJECT');
  assert.ok(r.score < 50);
  const f = ids(r.findings);
  assert.ok(f.includes('SELFDESTRUCT'));
  assert.ok(f.includes('UNPROTECTED_UPGRADE'));
  assert.ok(f.includes('REENTRANCY'));
  assert.ok(f.includes('CLAIM_VS_CODE_MISMATCH'));
  assert.ok(f.includes('PROXY_UPGRADE'));
});

test('risky fixture reviews (50-79) with no critical finding', () => {
  const r = analyzeProposal(riskyFixture);
  assert.equal(r.verdict, 'REVIEW');
  assert.ok(r.score >= 50 && r.score < 80);
  assert.equal(r.counts.bySeverity.critical, 0);
});

test('privacy fixture reviews and flags USER_DATA_COLLECTION + PLAINTEXT_PII', () => {
  const r = analyzeProposal(privacyFixture);
  assert.equal(r.verdict, 'REVIEW');
  const f = ids(r.findings);
  assert.ok(f.includes('USER_DATA_COLLECTION'));
  assert.ok(f.includes('PLAINTEXT_PII'));
});

test('reportMarkdown contains verdict, score and every finding', () => {
  const r = analyzeProposal(maliciousFixture);
  const md = reportMarkdown(r);
  assert.ok(md.includes('REJECT'));
  assert.ok(md.includes(`score ${r.score}/100`));
  assert.ok(md.includes('SELFDESTRUCT'));
  assert.ok(md.includes('UNPROTECTED_UPGRADE'));
});
