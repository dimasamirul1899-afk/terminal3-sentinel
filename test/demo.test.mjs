import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { FIXTURES } from '../docs/fixtures.js';
import { analyzeProposal } from '../docs/core.mjs';

// The browser demo must run the EXACT same code as the CLI and the tests.
// These tests fail the build if the generated demo files drift.
test('docs/core.mjs is byte-identical to src/core.mjs', async () => {
  const [a, b] = await Promise.all([
    readFile(new URL('../src/core.mjs', import.meta.url), 'utf8'),
    readFile(new URL('../docs/core.mjs', import.meta.url), 'utf8'),
  ]);
  assert.equal(b, a);
});

test('docs/fixtures.js embeds all four fixtures with their Solidity source', () => {
  const ids = Object.keys(FIXTURES).sort();
  assert.deepEqual(ids, [
    'prop-malicious-001',
    'prop-privacy-001',
    'prop-risky-001',
    'prop-safe-001',
  ]);
  for (const p of Object.values(FIXTURES)) {
    assert.ok(Array.isArray(p.code) && p.code.length > 0);
    assert.ok(p.code[0].source.includes('pragma solidity'));
  }
});

test('demo core analyses the fixtures exactly like the CLI core', () => {
  const expected = {
    'prop-malicious-001': 'REJECT',
    'prop-privacy-001': 'REVIEW',
    'prop-risky-001': 'REVIEW',
    'prop-safe-001': 'APPROVE',
  };
  for (const [id, verdict] of Object.entries(expected)) {
    assert.equal(analyzeProposal(FIXTURES[id]).verdict, verdict, id);
  }
});
