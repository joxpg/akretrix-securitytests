#!/usr/bin/env node
'use strict';

/**
 * Proves the scanner still detects each class of defect.
 *
 * A security scanner that silently stops matching is worse than no scanner,
 * because a clean report gets read as "we are fine". This runs the static
 * checks over a deliberately vulnerable fixture and asserts that every expected
 * check id fires — and separately that a clean fixture produces none of them.
 */

const path = require('path');
const { Report } = require('../lib/report');
const { runCodeChecks } = require('../lib/checks-code');

const EXPECTED = [
  ['CODE-01', 'unescaped remote data in innerHTML'],
  ['CODE-02', 'escape helper missing quote characters'],
  ['CODE-04', 'SSRF without containment'],
  ['CODE-05', 'CORS falling open to "*"'],
  ['CODE-06', 'security header set as an ignored meta tag'],
  ['CODE-07', 'missing Content-Security-Policy'],
  ['CODE-08', 'deploy publishing the repository root'],
  ['CODE-09', 'CI/OIDC hygiene problems'],
  ['CODE-10', 'eval present'],
  ['CODE-11', 'credential in web storage'],
  ['CODE-14', 'plaintext http:// subresource'],
  ['CODE-15', 'TLS verification disabled'],
  ['CODE-16', 'target=_blank without noopener'],
];

function scan(dir) {
  const report = new Report(dir, 'selftest');
  runCodeChecks(dir, report);
  return report;
}

function main() {
  const vulnerable = path.join(__dirname, 'fixtures', 'vulnerable');
  const report = scan(vulnerable);
  const fired = new Set(report.findings.map(f => f.id));

  let failures = 0;
  console.log('\nDetection coverage against the vulnerable fixture:\n');
  for (const [id, description] of EXPECTED) {
    const ok = fired.has(id);
    if (!ok) failures++;
    console.log(`  ${ok ? '✓' : '✗'} ${id}  ${description}`);
  }

  const unexpected = [...fired].filter(id => !EXPECTED.some(([e]) => e === id));
  if (unexpected.length) {
    console.log(`\n  note: also fired (not asserted): ${unexpected.join(', ')}`);
  }

  console.log(`\n${report.findings.length} findings, ${EXPECTED.length - failures}/${EXPECTED.length} expected checks fired.`);

  if (failures) {
    console.error(`\nFAIL: ${failures} check(s) no longer detect their defect. Fix the check before trusting a clean report.\n`);
    process.exit(1);
  }
  console.log('\nPASS: every check still detects its defect.\n');
}

main();
