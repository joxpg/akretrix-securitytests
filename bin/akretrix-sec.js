#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { Report, SEVERITIES, renderText, renderJson } = require('../lib/report');
const { runCodeChecks } = require('../lib/checks-code');
const { runUrlChecks } = require('../lib/checks-url');

const USAGE = `
akretrix-sec — security tests for AkreTrix frontends

  Static review of a checkout (no network):
    akretrix-sec code <path> [options]

  Runtime review of a deployed site:
    akretrix-sec url <url> [options]

Options:
  --json                 Machine-readable output for CI artefacts
  --fail-on <severity>   Exit 1 when a finding at or above this level exists.
                         One of: ${SEVERITIES.join(', ')}, never
                         Default: high
  --show-passed          List the checks that passed
  -h, --help             This message

Examples:
  akretrix-sec code ../akretrix-landing-page
  akretrix-sec code ./ --fail-on critical --json > security.json
  akretrix-sec url https://akretrix.com
  akretrix-sec url http://localhost:8080 --fail-on never --show-passed

Run the url mode only against properties your organisation controls.
`;

function parseArgs(argv) {
  const opts = { json: false, failOn: 'high', showPassed: false };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') opts.json = true;
    else if (arg === '--show-passed') opts.showPassed = true;
    else if (arg === '--fail-on') opts.failOn = argv[++i];
    else if (arg.startsWith('--fail-on=')) opts.failOn = arg.split('=')[1];
    else if (arg === '-h' || arg === '--help') opts.help = true;
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else positional.push(arg);
  }
  return { opts, positional };
}

async function main() {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${e.message}\n${USAGE}`);
    process.exit(2);
  }
  const { opts, positional } = parsed;
  const [mode, target] = positional;

  if (opts.help || !mode) {
    process.stdout.write(USAGE);
    process.exit(mode ? 0 : 2);
  }
  if (!SEVERITIES.includes(opts.failOn) && opts.failOn !== 'never') {
    process.stderr.write(`--fail-on must be one of: ${SEVERITIES.join(', ')}, never\n`);
    process.exit(2);
  }
  if (!target) {
    process.stderr.write(`Mode "${mode}" needs a target.\n${USAGE}`);
    process.exit(2);
  }

  let report;
  try {
    if (mode === 'code') {
      const root = path.resolve(target);
      if (!fs.existsSync(root)) throw new Error(`Path not found: ${root}`);
      if (!fs.statSync(root).isDirectory()) throw new Error(`Not a directory: ${root}`);
      report = new Report(root, 'static code review');
      runCodeChecks(root, report);
    } else if (mode === 'url') {
      const url = /^https?:\/\//.test(target) ? target : `https://${target}`;
      report = new Report(url, 'runtime review');
      await runUrlChecks(url, report);
    } else {
      throw new Error(`Unknown mode "${mode}". Use "code" or "url".`);
    }
  } catch (e) {
    process.stderr.write(`\nakretrix-sec failed: ${e.message}\n`);
    process.exit(2);
  }

  process.stdout.write(opts.json ? renderJson(report) + '\n' : renderText(report, { showPassed: opts.showPassed }));
  process.exit(report.shouldFail(opts.failOn) ? 1 : 0);
}

main();
