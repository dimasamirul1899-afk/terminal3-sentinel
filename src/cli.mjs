#!/usr/bin/env node
// Sentinel CLI — DAO proposal security agent.
// Usage:
//   node src/cli.mjs analyze <proposal.mjs|proposal.json> [--json]
//   node src/cli.mjs demo            # analyse all bundled fixtures
//   node src/cli.mjs detectors       # list detectors
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { analyzeProposal, reportMarkdown, CODE_DETECTORS } from './core.mjs';

async function loadProposal(path) {
  if (path.endsWith('.json')) {
    return JSON.parse(await readFile(path, 'utf8'));
  }
  const mod = await import(pathToFileURL(path).href);
  return mod.default ?? mod;
}

function printReport(report, asJson) {
  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  console.log(reportMarkdown(report));
  console.log(`\nExit code reflects verdict: ${report.verdict}`);
}

const [cmd, ...rest] = process.argv.slice(2);
const asJson = rest.includes('--json');
const target = rest.find((a) => !a.startsWith('--'));

if (cmd === 'analyze') {
  if (!target) {
    console.error('Usage: node src/cli.mjs analyze <proposal.mjs|proposal.json> [--json]');
    process.exit(2);
  }
  const proposal = await loadProposal(target);
  const report = analyzeProposal(proposal);
  printReport(report, asJson);
  process.exit(report.verdict === 'REJECT' ? 1 : 0);
}

if (cmd === 'demo') {
  const { readdir } = await import('node:fs/promises');
  const dir = new URL('../fixtures/', import.meta.url);
  const files = (await readdir(dir)).filter((f) => f.endsWith('.mjs')).sort();
  for (const file of files) {
    const proposal = await loadProposal(new URL(`../fixtures/${file}`, import.meta.url).pathname);
    const report = analyzeProposal(proposal);
    console.log(
      `${report.verdict.padEnd(7)}  score ${String(report.score).padStart(3)}/100  ` +
        `${report.counts.total} findings  ${report.title}`,
    );
  }
  process.exit(0);
}

if (cmd === 'detectors') {
  console.log('Code detectors:');
  for (const d of CODE_DETECTORS) console.log(`  - ${d.name}`);
  console.log('\nGovernance + privacy checks: TREASURY_DRAIN, LARGE_TREASURY_SPEND,');
  console.log('NO_TIMELOCK, SINGLE_SIGNER_EXECUTOR, SMALL_MULTISIG, PROXY_UPGRADE,');
  console.log('CLAIM_VS_CODE_MISMATCH, DIRECT_ETH_TO_EOA, VAGUE_DESCRIPTION,');
  console.log('NEW_PROPOSER, USER_DATA_COLLECTION');
  process.exit(0);
}

console.error('Usage: node src/cli.mjs <analyze <file> [--json] | demo | detectors>');
process.exit(2);
