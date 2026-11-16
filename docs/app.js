// Sentinel web demo — imports the exact same core the CLI and tests use.
import { analyzeProposal, reportMarkdown } from './core.mjs';
import { FIXTURES } from './fixtures.js';

const $ = (id) => document.getElementById(id);
const input = $('input');
const results = $('results');
const verdictEl = $('verdict');
const fixturesEl = $('fixtures');

const ORDER = ['prop-malicious-001', 'prop-risky-001', 'prop-privacy-001', 'prop-safe-001'];
const LABELS = {
  'prop-malicious-001': '☠ Malicious upgrade',
  'prop-risky-001': '⚠ Risky grant (15%)',
  'prop-privacy-001': '◉ Privacy-risk registry',
  'prop-safe-001': '✓ Safe diversification',
};

let lastReport = null;

for (const id of ORDER) {
  const p = FIXTURES[id];
  if (!p) continue;
  const b = document.createElement('button');
  b.textContent = LABELS[id] || p.title;
  b.title = p.title;
  b.addEventListener('click', () => {
    document.querySelectorAll('.fixtures button').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    input.value = JSON.stringify(p, null, 2);
    run();
  });
  fixturesEl.appendChild(b);
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function render(report) {
  const c = report.counts;
  const color = report.verdict === 'APPROVE' ? 'var(--green)' : report.verdict === 'REVIEW' ? 'var(--amber)' : 'var(--red)';
  verdictEl.style.display = 'block';
  verdictEl.innerHTML = `
    <div class="verdict-card ${report.verdict}">
      <div>
        <div class="verdict-word">${report.verdict}</div>
        <div style="color:var(--muted);font-size:13px">${esc(report.title ?? '')}</div>
      </div>
      <div class="score">
        <b>${report.score}<span style="font-size:14px;color:var(--muted)">/100</span></b>
        <span>risk score</span>
        <div class="bar"><i style="width:${report.score}%;background:${color}"></i></div>
      </div>
    </div>
    <p style="margin:0 0 12px">${esc(report.summary)}</p>
    <div class="counts">findings: ${c.total} · critical ${c.bySeverity.critical} · high ${c.bySeverity.high} · medium ${c.bySeverity.medium} · low ${c.bySeverity.low} · info ${c.bySeverity.info}</div>`;

  if (report.findings.length === 0) {
    results.innerHTML = '<div class="empty">No findings. Clean proposal.</div>';
    return;
  }
  results.innerHTML = report.findings
    .map(
      (f) => `
    <div class="finding ${f.severity}">
      <h3><span class="chip ${f.severity}">${f.severity}</span>${esc(f.title)}</h3>
      <div class="meta">${esc(f.id)} · ${esc(f.category)}${f.file ? ` · ${esc(f.file)}` : ''}${f.line ? ` · line ${f.line}` : ''}</div>
      <p>${esc(f.detail)}</p>
      ${f.evidence ? `<pre>${esc(f.evidence)}</pre>` : ''}
    </div>`,
    )
    .join('');
}

function run() {
  let proposal;
  try {
    proposal = JSON.parse(input.value);
  } catch (e) {
    results.innerHTML = `<div class="empty" style="color:var(--red)">Invalid JSON: ${esc(e.message)}</div>`;
    verdictEl.style.display = 'none';
    return;
  }
  if (!proposal || typeof proposal !== 'object') {
    results.innerHTML = '<div class="empty" style="color:var(--red)">Proposal must be a JSON object.</div>';
    verdictEl.style.display = 'none';
    return;
  }
  lastReport = analyzeProposal(proposal);
  render(lastReport);
}

$('run').addEventListener('click', run);
$('copy').addEventListener('click', async () => {
  if (!lastReport) return;
  try {
    await navigator.clipboard.writeText(reportMarkdown(lastReport));
    $('copy').textContent = 'Copied ✓';
    setTimeout(() => ($('copy').textContent = 'Copy markdown report'), 1500);
  } catch {
    $('copy').textContent = 'Copy failed — select the report manually';
  }
});

// Load the malicious fixture by default so the first paint shows the agent working.
const first = document.querySelector('.fixtures button');
if (first) first.click();
