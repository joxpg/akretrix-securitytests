'use strict';

/**
 * Shared severity model, reporting and exit-code policy.
 *
 * Every check returns findings through this so the two scanners behave
 * identically in CI: same severity names, same ordering, same exit codes.
 */

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const RANK = SEVERITIES.reduce((acc, s, i) => ({ ...acc, [s]: i }), {});

/**
 * Confidence matters for static analysis. A regex can prove that a tag is
 * present, but it cannot prove that a value reaching innerHTML is attacker
 * controlled — that needs a human. Saying so keeps the report trustworthy
 * instead of drowning real findings in guesses.
 */
const CONFIDENCE = {
  CONFIRMED: 'confirmed', // the condition is definitively true as written
  LIKELY: 'likely',       // strong signal, small chance of a false positive
  REVIEW: 'review',       // needs a human to judge; reported so it is not missed
};

class Report {
  constructor(target, mode) {
    this.target = target;
    this.mode = mode;
    this.findings = [];
    this.passed = [];
  }

  add({ id, title, severity, confidence = CONFIDENCE.CONFIRMED, where, detail, remediation }) {
    if (!RANK.hasOwnProperty(severity)) throw new Error(`Unknown severity: ${severity}`);
    this.findings.push({ id, title, severity, confidence, where, detail, remediation });
  }

  pass(id, title) {
    this.passed.push({ id, title });
  }

  counts() {
    return this.findings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {});
  }

  sorted() {
    return [...this.findings].sort((a, b) => {
      if (RANK[a.severity] !== RANK[b.severity]) return RANK[a.severity] - RANK[b.severity];
      return String(a.id).localeCompare(String(b.id));
    });
  }

  /** True when anything at or above the threshold was found. */
  shouldFail(threshold) {
    if (threshold === 'never') return false;
    const limit = RANK[threshold];
    if (limit === undefined) throw new Error(`Unknown --fail-on value: ${threshold}`);
    return this.findings.some(f => RANK[f.severity] <= limit);
  }
}

const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, s) => (COLOR ? `[${code}m${s}[0m` : s);
const SEV_STYLE = {
  critical: s => paint('1;41;97', ` ${s} `),
  high: s => paint('1;31', s),
  medium: s => paint('1;33', s),
  low: s => paint('36', s),
  info: s => paint('2', s),
};

function renderText(report, { showPassed }) {
  const lines = [];
  lines.push('');
  lines.push(paint('1', `AkreTrix security tests — ${report.mode}`));
  lines.push(`target: ${report.target}`);
  lines.push('');

  const sorted = report.sorted();
  if (!sorted.length) {
    lines.push(paint('1;32', 'No findings.'));
  } else {
    for (const f of sorted) {
      const sev = (SEV_STYLE[f.severity] || (s => s))(f.severity.toUpperCase());
      const conf = f.confidence === CONFIDENCE.CONFIRMED ? '' : paint('2', ` (${f.confidence})`);
      lines.push(`${sev} ${paint('1', f.id)} ${f.title}${conf}`);
      if (f.where) lines.push(`  where: ${f.where}`);
      if (f.detail) lines.push(`  ${f.detail}`);
      if (f.remediation) lines.push(`  ${paint('2', 'fix:')} ${f.remediation}`);
      lines.push('');
    }
  }

  if (showPassed && report.passed.length) {
    lines.push(paint('1', 'Passed'));
    for (const p of report.passed) lines.push(`  ${paint('32', '✓')} ${p.id} ${p.title}`);
    lines.push('');
  }

  const c = report.counts();
  const summary = SEVERITIES
    .filter(s => c[s])
    .map(s => `${c[s]} ${s}`)
    .join(', ') || 'nothing';
  lines.push(`${paint('1', 'Summary:')} ${summary} · ${report.passed.length} checks passed`);
  lines.push('');
  return lines.join('\n');
}

function renderJson(report) {
  return JSON.stringify(
    {
      mode: report.mode,
      target: report.target,
      counts: report.counts(),
      findings: report.sorted(),
      passed: report.passed,
    },
    null,
    2
  );
}

module.exports = { Report, SEVERITIES, CONFIDENCE, renderText, renderJson };
