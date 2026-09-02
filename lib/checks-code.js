'use strict';

/**
 * Static checks against a local checkout.
 *
 * Every check here exists because it caught a real defect in an AkreTrix
 * frontend. The "origin" note on each one records which, so nobody deletes a
 * check thinking it is theoretical.
 */

const fs = require('fs');
const path = require('path');
const { readTextFiles, lineOf, metaContent } = require('./walk');
const { CONFIDENCE } = require('./report');
const { findSecrets } = require('./secrets');

/* Anything that compiles to an HTML document, not just literal .html.
   Making these files readable is not sufficient: the HTML-specific checks
   (ignored meta headers, CSP presence) classify by extension, so a template
   language missing from this list means those checks silently skip an entire
   frontend while the report still lists them as passing. */
const HTML_EXT = new Set(['.html', '.htm', '.astro', '.mdx', '.hbs', '.ejs', '.njk', '.liquid', '.erb', '.twig', '.php', '.vue', '.svelte']);
const isHtml = f => HTML_EXT.has(f.ext);

/* Template languages embed <script> blocks, so they are script-bearing too. */
const SCRIPT_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.astro', '.vue', '.svelte']);
const isScript = f => SCRIPT_EXT.has(f.ext);
const isWorkflow = f => /\.github[/\\]workflows[/\\]/.test(f.rel) && ['.yml', '.yaml'].includes(f.ext);

/* ------------------------------------------------------------------------- *
 * CODE-01  Unescaped values reaching an HTML sink
 *
 * Origin: dns-report.html and dns-propagation.html interpolated DNS record
 * values straight into innerHTML. A TXT record is arbitrary attacker-supplied
 * text, so looking up a hostile domain executed its markup. Proven exploitable.
 * ------------------------------------------------------------------------- */

const HTML_SINKS = [
  { re: /\.innerHTML\s*\+?=/g, name: 'innerHTML' },
  { re: /\.outerHTML\s*\+?=/g, name: 'outerHTML' },
  { re: /\.insertAdjacentHTML\s*\(/g, name: 'insertAdjacentHTML' },
  { re: /document\.write(?:ln)?\s*\(/g, name: 'document.write' },
];

/** Interpolations that cannot introduce markup. */
const SAFE_INTERPOLATION = [
  /^\s*escapeHtml?\s*\(/i,
  /^\s*escape[A-Za-z]*\s*\(/,
  /^\s*sanitize[A-Za-z]*\s*\(/i,
  /^\s*DOMPurify\.sanitize\s*\(/,
  /^\s*encodeURI(?:Component)?\s*\(/,
  /^\s*Number\s*\(/,
  /^\s*parseInt\s*\(/,
  /^\s*parseFloat\s*\(/,
  /^\s*\d+(\.\d+)?\s*$/,
  /\.length\s*$/,
  /^\s*t\s*\(\s*['"][^'"]*['"]\s*(,[^)]*)?\)\s*$/, // i18n lookup of a literal key
  /^\s*['"][^'"]*['"]\s*$/,                        // string literal
];

/** Walks forward from a sink to the end of the assigned expression. */
function expressionAfter(content, from) {
  let i = from;
  let depthParen = 0;
  let depthBrace = 0;
  let quote = null;
  const limit = Math.min(content.length, from + 4000);
  for (; i < limit; i++) {
    const c = content[i];
    const prev = content[i - 1];
    if (quote) {
      if (c === quote && prev !== '\\') quote = null;
      continue;
    }
    if (c === '`' || c === '"' || c === "'") { quote = c; continue; }
    if (c === '(') depthParen++;
    else if (c === ')') { if (depthParen === 0) break; depthParen--; }
    else if (c === '{') depthBrace++;
    else if (c === '}') { if (depthBrace === 0) break; depthBrace--; }
    else if (c === ';' && depthParen === 0 && depthBrace === 0) break;
  }
  return content.slice(from, i);
}

/** Pulls `${...}` bodies out of an expression, respecting nesting. */
function interpolationsIn(expr) {
  const out = [];
  for (let i = 0; i < expr.length - 1; i++) {
    if (expr[i] === '$' && expr[i + 1] === '{') {
      let depth = 1;
      let j = i + 2;
      for (; j < expr.length && depth > 0; j++) {
        if (expr[j] === '{') depth++;
        else if (expr[j] === '}') depth--;
      }
      out.push({ body: expr.slice(i + 2, j - 1), offset: i });
      i = j - 1;
    }
  }
  return out;
}

function checkHtmlSinks(files, report) {
  let flagged = 0;
  let sinksSeen = 0;

  for (const file of files) {
    if (!isHtml(file) && !isScript(file)) continue;
    for (const sink of HTML_SINKS) {
      sink.re.lastIndex = 0;
      let m;
      while ((m = sink.re.exec(file.content))) {
        sinksSeen++;
        const expr = expressionAfter(file.content, m.index);
        const interps = interpolationsIn(expr);
        const unsafe = interps.filter(v => !SAFE_INTERPOLATION.some(re => re.test(v.body)));
        if (!unsafe.length) continue;
        flagged++;
        const line = lineOf(file.content, m.index);
        const sample = unsafe.slice(0, 4).map(v => '${' + v.body.trim().slice(0, 60) + '}').join(', ');
        report.add({
          id: 'CODE-01',
          title: `Unescaped value interpolated into ${sink.name}`,
          severity: 'high',
          confidence: CONFIDENCE.REVIEW,
          where: `${file.rel}:${line}`,
          detail: `Interpolated without an escaping call: ${sample}. If any of these can carry remote or user-supplied text, this is XSS.`,
          remediation: 'Wrap each value in escapeHtml(), or build the node and assign textContent instead of innerHTML.',
        });
      }
    }
  }

  if (sinksSeen && !flagged) report.pass('CODE-01', `All ${sinksSeen} HTML sink writes use escaped or literal values`);
  if (!sinksSeen) report.pass('CODE-01', 'No innerHTML/document.write sinks found');
}

/* ------------------------------------------------------------------------- *
 * CODE-02  Escaping helper completeness
 *
 * Origin: an existing escapeHtml() covered & < > but not quotes. Safe in text
 * position, unsafe the moment a value lands inside an attribute.
 * ------------------------------------------------------------------------- */
function checkEscapeHelper(files, report) {
  let found = 0;
  for (const file of files) {
    const re = /function\s+escapeHtml?\s*\([\s\S]{0,600}?\n\s*\}/gi;
    let m;
    while ((m = re.exec(file.content))) {
      found++;
      const body = m[0];
      const missing = [];
      if (!/&amp;/.test(body)) missing.push('&');
      if (!/&lt;/.test(body)) missing.push('<');
      if (!/&gt;/.test(body)) missing.push('>');
      if (!/&quot;|&#0?34;/.test(body)) missing.push('"');
      if (!/&#0?39;|&apos;/.test(body)) missing.push("'");
      if (missing.length) {
        report.add({
          id: 'CODE-02',
          title: 'Escaping helper does not cover every dangerous character',
          severity: missing.some(c => c === '<' || c === '>' || c === '&') ? 'high' : 'low',
          where: `${file.rel}:${lineOf(file.content, m.index)}`,
          detail: `Not escaped: ${missing.join(' ')}. Unescaped quotes are exploitable as soon as a value is placed inside an HTML attribute.`,
          remediation: 'Escape & < > " and \' so the helper is safe in both text and attribute position.',
        });
      }
    }
  }
  if (found) report.pass('CODE-02', `Reviewed ${found} escaping helper(s)`);
}

/* ------------------------------------------------------------------------- *
 * CODE-03  Committed secrets
 *
 * Patterns live in lib/secrets.js and are shared with the runtime scanners, so
 * "is it committed?" and "is it being served?" can never fall out of step.
 * ------------------------------------------------------------------------- */
function checkSecrets(files, report) {
  let hits = 0;
  for (const file of files) {
    if (/\.md$/.test(file.rel) && /example|sample/i.test(file.content.slice(0, 400))) continue;
    for (const hit of findSecrets(file.content)) {
      hits++;
      report.add({
        id: 'CODE-03',
        title: `Possible ${hit.what} committed to the repository`,
        severity: hit.severity,
        confidence: CONFIDENCE.LIKELY,
        where: `${file.rel}:${lineOf(file.content, hit.index)}`,
        // Redacted on purpose: this report gets attached to CI runs and pasted
        // into tickets, so printing the value in full would make the report a
        // second place the credential is exposed.
        detail: `Matched ${hit.what}: ${hit.redacted}. Anything committed must be treated as disclosed, even after deletion — git history keeps it.`,
        remediation: 'Rotate the credential now, then purge it from history and move it to a secret store.',
      });
    }
  }
  if (!hits) report.pass('CODE-03', 'No credential patterns found in tracked source');
}

/* ------------------------------------------------------------------------- *
 * CODE-04  SSRF: outbound connections built from request input
 *
 * Origin: the free-tools Lambda dialled any host/port/URL from an
 * unauthenticated query string. Two guards are required, and the first attempt
 * shipped only one — a lookup hook — which silently missed IP literals because
 * Node connects straight to a literal and never calls the hook.
 * ------------------------------------------------------------------------- */
function checkSsrf(files, report) {
  const DIALS = /\b(?:net\.(?:connect|createConnection)|socket\.connect|tls\.connect|https?\.request|https?\.get|fetch|axios|request)\s*\(/;
  const REQUEST_INPUT = /\b(?:queryStringParameters|req\.query|request\.query|event\.query|params\.(?:host|url|target|domain)|searchParams\.get|body\.(?:host|url|target))\b/;

  for (const file of files) {
    if (!isScript(file)) continue;
    if (!DIALS.test(file.content) || !REQUEST_INPUT.test(file.content)) continue;

    const hasLiteralGuard = /isIP\s*\(|assertConnectableHost|isBlocked|isPrivate|privateRange|BLOCKED_V4/i.test(file.content);
    const hasLookupGuard = /lookup\s*:/.test(file.content) && /dns\.lookup/.test(file.content);
    const hasSchemeGuard = /protocol\s*!==?\s*['"]https?:|allowedProtocols|parsePublicUrl/.test(file.content);

    const missing = [];
    if (!hasLiteralGuard) missing.push('no IP-literal rejection (a bare ?host=127.0.0.1 bypasses a DNS-only guard entirely)');
    if (!hasLookupGuard) missing.push('no validation inside the connection\'s DNS lookup (leaves a DNS-rebinding window)');
    if (!hasSchemeGuard) missing.push('no http/https scheme allow-list');

    if (missing.length) {
      report.add({
        id: 'CODE-04',
        title: 'Outbound request built from request input without full SSRF containment',
        severity: 'critical',
        confidence: CONFIDENCE.LIKELY,
        where: file.rel,
        detail: `This file dials a network target derived from request parameters. Missing: ${missing.join('; ')}.`,
        remediation: 'Reject IP literals up front AND validate resolved addresses inside a custom dns lookup passed to the connection. Block loopback, RFC1918, CGNAT, link-local (cloud metadata), multicast and reserved ranges for v4, v6 and v4-mapped v6.',
      });
    } else {
      report.pass('CODE-04', `${file.rel} has literal, lookup and scheme guards`);
    }
  }
}

/* ------------------------------------------------------------------------- *
 * CODE-05  Permissive CORS
 *
 * Origin: the API fell back to `ALLOWED_ORIGIN || '*'`, and its IaC defaulted
 * the parameter to "*", so a deploy with an unset secret shipped an API any
 * site could drive — silently.
 * ------------------------------------------------------------------------- */
function checkCors(files, report) {
  let issues = 0;
  for (const file of files) {
    const patterns = [
      { re: /ALLOWED_ORIGIN\s*\|\|\s*['"]\*['"]/g, why: 'CORS origin falls back to "*" when the env var is unset' },
      { re: /Access-Control-Allow-Origin['"]\s*[:,]\s*['"]\*['"]/g, why: 'Access-Control-Allow-Origin is hardcoded to "*"' },
      { re: /AllowOrigins?\s*:\s*\n?\s*-?\s*['"]\*['"]/g, why: 'IaC allows any origin' },
      { re: /Default\s*:\s*["']\*["']/g, why: 'IaC parameter defaults to "*", so a missing value ships permissive CORS' },
    ];
    for (const { re, why } of patterns) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(file.content))) {
        issues++;
        report.add({
          id: 'CODE-05',
          title: 'Permissive or fail-open CORS configuration',
          severity: 'high',
          where: `${file.rel}:${lineOf(file.content, m.index)}`,
          detail: why,
          remediation: 'Require an explicit origin. Emit no Access-Control-Allow-Origin when unconfigured, and drop the wildcard default from IaC so a missing value fails the deploy.',
        });
      }
    }
  }
  if (!issues) report.pass('CODE-05', 'No wildcard or fail-open CORS configuration');
}

/* ------------------------------------------------------------------------- *
 * CODE-06  Security headers set as <meta>, where browsers ignore them
 *
 * Origin: every page carried <meta http-equiv="X-Content-Type-Options">, and
 * the README claimed nosniff was active. Browsers honour that header only over
 * HTTP, so the protection did not exist. False assurance is worse than a known
 * gap, because nobody goes looking for it.
 * ------------------------------------------------------------------------- */
const META_ONLY_IGNORED = [
  'x-content-type-options',
  'x-frame-options',
  'strict-transport-security',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'x-xss-protection',
];

function checkIneffectiveMeta(files, report) {
  let issues = 0;
  for (const file of files) {
    if (!isHtml(file)) continue;
    const re = /<meta\s+http-equiv=["']([^"']+)["']/gi;
    let m;
    while ((m = re.exec(file.content))) {
      const name = m[1].toLowerCase();
      if (!META_ONLY_IGNORED.includes(name)) continue;
      issues++;
      report.add({
        id: 'CODE-06',
        title: `"${m[1]}" set as a meta tag has no effect`,
        severity: 'medium',
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: 'Browsers honour this only as a real HTTP response header. As a meta tag it is silently ignored, which reads as protection that is not there.',
        remediation: 'Remove the meta tag and set the header at the CDN or origin (e.g. a CloudFront response-headers policy). Only Content-Security-Policy and Referrer-Policy work from meta.',
      });
    }
  }
  if (!issues) report.pass('CODE-06', 'No security headers relying on an ignored meta tag');
}

/* ------------------------------------------------------------------------- *
 * CODE-07  CSP presence and strength in delivered HTML
 * ------------------------------------------------------------------------- */
/* A CSP belongs in whichever file emits the document <head>. In a component or
   layout architecture that is one shared layout, and the pages that use it carry
   no <head> of their own — judging those would report a missing policy on every
   page of a site that serves one correctly, which is pure noise. So only files
   that actually emit a full document are held to this. */
const emitsFullDocument = f => /<!doctype\s+html|<html[\s>]/i.test(f.content);

function checkCsp(files, report) {
  const pages = files.filter(f => isHtml(f) && emitsFullDocument(f));
  if (!pages.length) {
    const partials = files.filter(isHtml).length;
    if (partials) {
      report.add({
        id: 'CODE-07',
        title: 'No file emits a full HTML document, so no CSP could be located',
        severity: 'medium',
        confidence: CONFIDENCE.REVIEW,
        where: `${partials} template file(s)`,
        detail: 'Every template appears to be a partial. If the document shell is generated elsewhere (a framework default, or an SSR adapter), confirm a Content-Security-Policy is set there — this check could not see it.',
        remediation: 'Set the CSP in the layout that emits <head>, or as a response header at the CDN.',
      });
    }
    return;
  }

  for (const file of pages) {
    const csp = metaContent(file.content, 'Content-Security-Policy');
    if (!csp) {
      report.add({
        id: 'CODE-07',
        title: 'Page defines no Content-Security-Policy',
        severity: 'medium',
        where: file.rel,
        detail: 'With no CSP, any successful HTML injection runs with full privileges and can exfiltrate to any host.',
        remediation: 'Add a CSP (meta works for this one) or serve it as a header. At minimum set default-src, object-src \'none\' and base-uri \'none\'.',
      });
      continue;
    }
    const weak = [];
    if (/script-src[^;]*'unsafe-inline'/.test(csp)) weak.push("script-src allows 'unsafe-inline', which defeats most of the XSS benefit");
    if (/script-src[^;]*'unsafe-eval'/.test(csp)) weak.push("script-src allows 'unsafe-eval'");
    if (/script-src[^;]*\*(?!\.)/.test(csp)) weak.push('script-src contains a bare wildcard');
    if (!/object-src/.test(csp)) weak.push("object-src is unset (should be 'none')");
    if (!/base-uri/.test(csp)) weak.push("base-uri is unset (should be 'none'; a stray <base> can redirect every relative URL)");
    if (weak.length) {
      report.add({
        id: 'CODE-07',
        title: 'Content-Security-Policy is weaker than it should be',
        severity: 'low',
        where: file.rel,
        detail: weak.join('; ') + '.',
        remediation: "Move inline <script> blocks into external files so 'unsafe-inline' can be dropped, and set object-src/base-uri to 'none'.",
      });
    } else {
      report.pass('CODE-07', `${file.rel} has a CSP with no obvious weakness`);
    }
  }
}

/* ------------------------------------------------------------------------- *
 * CODE-08  What the deploy actually publishes
 *
 * Origin: the workflow ran `aws s3 sync ./` against a public bucket with five
 * ad-hoc excludes, so .claude/, AGENTS.md, tests/ and any future root-level
 * dotfile were published. A deny-list is the wrong shape for this.
 * ------------------------------------------------------------------------- */
function checkPublishSurface(files, report) {
  let issues = 0;
  for (const file of files) {
    if (!isWorkflow(file) && !/deploy|publish/i.test(file.rel)) continue;
    const re = /aws\s+s3\s+(?:sync|cp)\s+(\S+)/g;
    let m;
    while ((m = re.exec(file.content))) {
      const src = m[1];
      const rootish = src === './' || src === '.' || src === '"./"' || src === './.';
      if (!rootish) continue;
      issues++;
      const usesDenyList = /--exclude/.test(file.content);
      report.add({
        id: 'CODE-08',
        title: 'Deploy publishes the repository root to a public bucket',
        severity: 'high',
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: usesDenyList
          ? 'Syncing the repo root and subtracting a few --exclude paths is a deny-list: everything not thought of ships publicly, including dotfiles and local config added later.'
          : 'Syncing the repo root publishes every file in the checkout.',
        remediation: 'Sync only the built site directory (e.g. ./frontend or ./dist) so publishing is an allow-list by construction.',
      });
    }
  }
  if (!issues) report.pass('CODE-08', 'Deploy publishes a specific site directory, not the repo root');
}

/* ------------------------------------------------------------------------- *
 * CODE-09  CI and OIDC hygiene
 *
 * Origin: the trust policy ended in `:*`, letting any branch assume the
 * production deploy role.
 * ------------------------------------------------------------------------- */
function checkCiHygiene(files, report) {
  for (const file of files) {
    // Over-broad OIDC subject, wherever it is documented or defined.
    const sub = /token\.actions\.githubusercontent\.com:sub["']?\s*:\s*["']([^"']+)["']/g;
    let m;
    while ((m = sub.exec(file.content))) {
      if (/:\*"?$/.test(m[1]) || m[1].endsWith(':*')) {
        report.add({
          id: 'CODE-09',
          title: 'OIDC trust policy is not scoped to a branch',
          severity: 'medium',
          where: `${file.rel}:${lineOf(file.content, m.index)}`,
          detail: `Subject "${m[1]}" ends in a wildcard, so any branch — or any pull request ref — can assume this role and deploy.`,
          remediation: 'Pin production to ref:refs/heads/main and give QA a separate role/ref.',
        });
      }
    }

    if (!isWorkflow(file)) continue;

    // Unpinned third-party actions.
    const uses = /uses:\s*([^\s@]+)@(\S+)/g;
    while ((m = uses.exec(file.content))) {
      const [, action, ref] = m;
      if (action.startsWith('./') || action.startsWith('actions/')) continue;
      if (/^(main|master|latest|v\d+)$/.test(ref) && !/^[0-9a-f]{40}$/.test(ref)) {
        report.add({
          id: 'CODE-09',
          title: `Third-party action "${action}" is pinned to a mutable ref`,
          severity: 'low',
          where: `${file.rel}:${lineOf(file.content, m.index)}`,
          detail: `Pinned to "${ref}", which the owner can move. A compromised or retagged action runs with your OIDC permissions.`,
          remediation: 'Pin third-party actions to a full commit SHA.',
        });
      }
    }

    // Write permissions that a deploy rarely needs.
    if (/permissions:/.test(file.content) && /contents:\s*write/.test(file.content)) {
      report.add({
        id: 'CODE-09',
        title: 'Workflow grants contents: write',
        severity: 'low',
        where: file.rel,
        detail: 'A deploy job normally needs only contents: read plus id-token: write.',
        remediation: 'Reduce to the minimum token scope the job actually uses.',
      });
    }

    // Untrusted input interpolated into a shell step.
    const risky = /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|head_commit)[^}]*\}\}/g;
    while ((m = risky.exec(file.content))) {
      report.add({
        id: 'CODE-09',
        title: 'Attacker-controllable github.event data interpolated into a workflow',
        severity: 'high',
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: 'PR titles, branch names and comment bodies are attacker-controlled. Interpolated into a run: block they become shell injection.',
        remediation: 'Pass the value through env: and reference "$VAR" inside the script, quoted.',
      });
    }
  }
}

/* ------------------------------------------------------------------------- *
 * CODE-10  Dangerous JS APIs and navigation sinks
 * ------------------------------------------------------------------------- */
function checkDangerousApis(files, report) {
  const patterns = [
    { re: /\beval\s*\(/g, title: 'eval() present', sev: 'high' },
    { re: /new\s+Function\s*\(/g, title: 'new Function() present', sev: 'high' },
    { re: /setTimeout\s*\(\s*['"`]/g, title: 'setTimeout called with a string body', sev: 'medium' },
    { re: /setInterval\s*\(\s*['"`]/g, title: 'setInterval called with a string body', sev: 'medium' },
    { re: /\.srcdoc\s*=/g, title: 'iframe srcdoc assigned dynamically', sev: 'medium' },
    { re: /addEventListener\s*\(\s*['"]message['"]/g, title: 'postMessage listener — verify event.origin is checked', sev: 'medium' },
  ];
  let issues = 0;
  for (const file of files) {
    if (!isScript(file) && !isHtml(file)) continue;
    for (const { re, title, sev } of patterns) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(file.content))) {
        issues++;
        report.add({
          id: 'CODE-10',
          title,
          severity: sev,
          confidence: CONFIDENCE.REVIEW,
          where: `${file.rel}:${lineOf(file.content, m.index)}`,
          detail: 'Turns string data into executable code, or accepts messages from any frame.',
          remediation: 'Remove the dynamic-code path. For message listeners, compare event.origin against an explicit allow-list before trusting the payload.',
        });
      }
    }
  }
  if (!issues) report.pass('CODE-10', 'No eval/new Function/string-timer/message-listener risks found');
}

/* ------------------------------------------------------------------------- *
 * CODE-11  Sensitive data in web storage
 * ------------------------------------------------------------------------- */
function checkWebStorage(files, report) {
  let issues = 0;
  const re = /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`]([^'"`]+)['"`]/g;
  for (const file of files) {
    if (!isScript(file) && !isHtml(file)) continue;
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(file.content))) {
      if (!/token|secret|password|passwd|jwt|session|auth|credential|api[-_]?key|bearer/i.test(m[1])) continue;
      issues++;
      report.add({
        id: 'CODE-11',
        title: `Sensitive-looking value written to web storage ("${m[1]}")`,
        severity: 'high',
        confidence: CONFIDENCE.LIKELY,
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: 'Web storage is readable by any script on the origin, so one XSS turns into credential theft. It is also not cleared on tab close.',
        remediation: 'Keep session material in a Secure, HttpOnly, SameSite cookie. Reserve web storage for non-sensitive UI preferences.',
      });
    }
  }
  if (!issues) report.pass('CODE-11', 'Web storage holds no sensitive-looking keys');
}

/* ------------------------------------------------------------------------- *
 * CODE-12  Path traversal in a static file server
 * ------------------------------------------------------------------------- */
function checkPathTraversal(files, report) {
  for (const file of files) {
    if (!isScript(file)) continue;
    const joins = /path\.join\s*\([^)]*(?:req\.url|parsedUrl\.pathname|pathname|req\.path)[^)]*\)/g;
    let m;
    while ((m = joins.exec(file.content))) {
      const contained = /startsWith\s*\(|\.resolve\s*\([^)]*\)\s*\.startsWith|relative\s*\(/.test(file.content);
      report.add({
        id: 'CODE-12',
        title: contained
          ? 'Static file path built from the request URL (containment check present)'
          : 'Static file path built from the request URL with no containment check',
        severity: contained ? 'info' : 'high',
        confidence: contained ? CONFIDENCE.CONFIRMED : CONFIDENCE.LIKELY,
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: contained
          ? 'A containment check was found in this file; confirm it runs on every branch that reads a file.'
          : 'Without a check that the resolved path stays inside the web root, ../ escapes it and serves arbitrary files.',
        remediation: 'After path.join (which normalises ..), verify the result starts with the web root plus a separator, and reject otherwise.',
      });
    }
  }
}

/* ------------------------------------------------------------------------- *
 * CODE-13  Dependency hygiene
 * ------------------------------------------------------------------------- */
function checkDependencies(root, files, report) {
  const manifests = files.filter(f => path.basename(f.rel) === 'package.json' && !f.rel.includes('node_modules'));
  for (const manifest of manifests) {
    let pkg;
    try {
      pkg = JSON.parse(manifest.content);
    } catch {
      continue;
    }
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    if (!Object.keys(deps).length) {
      report.pass('CODE-13', `${manifest.rel} declares no dependencies (nothing to audit)`);
      continue;
    }
    const dir = path.dirname(path.join(root, manifest.rel));
    const hasLock = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml']
      .some(l => fs.existsSync(path.join(dir, l)));
    if (!hasLock) {
      report.add({
        id: 'CODE-13',
        title: 'Dependencies declared with no lockfile',
        severity: 'medium',
        where: manifest.rel,
        detail: 'Without a lockfile every install can resolve different transitive versions, so a build is not reproducible and cannot be audited reliably.',
        remediation: 'Commit a lockfile and run `npm audit --omit=dev` in CI.',
      });
    }
    const loose = Object.entries(deps).filter(([, v]) => typeof v === 'string' && /^[*x]$|^latest$/.test(v));
    if (loose.length) {
      report.add({
        id: 'CODE-13',
        title: 'Dependency pinned to a floating version',
        severity: 'medium',
        where: manifest.rel,
        detail: `Unbounded ranges: ${loose.map(([k, v]) => `${k}@${v}`).join(', ')}.`,
        remediation: 'Use a bounded range and rely on the lockfile.',
      });
    }
  }
}

/* ------------------------------------------------------------------------- *
 * CODE-14/15/16  Mixed content, disabled TLS verification, tabnabbing
 * ------------------------------------------------------------------------- */
function checkTransportAndLinks(files, report) {
  let mixed = 0;
  let tlsOff = 0;
  let tabnab = 0;

  for (const file of files) {
    // 14: plaintext subresources
    const http = /(?:src|href)=["']http:\/\/(?!localhost|127\.0\.0\.1)([^"']+)["']/g;
    let m;
    while ((m = http.exec(file.content))) {
      mixed++;
      report.add({
        id: 'CODE-14',
        title: 'Resource referenced over plaintext http://',
        severity: 'medium',
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: `http://${m[1].slice(0, 60)} — on an HTTPS page this is blocked as mixed content or downgrades the request.`,
        remediation: 'Use https://, or a root-relative path for first-party assets.',
      });
    }

    // 15: TLS verification switched off
    const off = /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|curl[^\n]*\s-k\b|--insecure\b/g;
    while ((m = off.exec(file.content))) {
      tlsOff++;
      report.add({
        id: 'CODE-15',
        title: 'TLS certificate verification disabled',
        severity: 'high',
        confidence: CONFIDENCE.REVIEW,
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: 'Any response on this connection can be forged by a network attacker. Legitimate only for a tool whose job is inspecting an untrusted certificate — and then only if the response body is not trusted.',
        remediation: 'Leave verification on. If a certificate inspector genuinely needs it off, confine it to that call and document why next to the code.',
      });
    }

    // 16: target=_blank without noopener
    const blank = /<a\b[^>]*target=["']_blank["'][^>]*>/gi;
    while ((m = blank.exec(file.content))) {
      if (/rel=["'][^"']*noopener/i.test(m[0])) continue;
      tabnab++;
      report.add({
        id: 'CODE-16',
        title: 'target="_blank" without rel="noopener"',
        severity: 'low',
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: 'The opened page receives a window.opener handle and can navigate this tab elsewhere (reverse tabnabbing).',
        remediation: 'Add rel="noopener noreferrer".',
      });
    }
  }

  if (!mixed) report.pass('CODE-14', 'No plaintext http:// subresources');
  if (!tlsOff) report.pass('CODE-15', 'TLS verification is not disabled anywhere');
  if (!tabnab) report.pass('CODE-16', 'All target="_blank" links set rel="noopener"');
}

/* ------------------------------------------------------------------------- *
 * CODE-17  Electron process isolation & WebPreferences hardening
 * ------------------------------------------------------------------------- */
function checkElectronSecurity(files, report) {
  const electronFiles = files.filter(f => isScript(f) && /(?:webPreferences|BrowserWindow|contextBridge|app\.enableSandbox)/.test(f.content));
  if (!electronFiles.length) return;

  let issues = 0;
  for (const file of electronFiles) {
    const badPatterns = [
      { re: /nodeIntegration\s*:\s*true/g, name: 'nodeIntegration: true' },
      { re: /contextIsolation\s*:\s*false/g, name: 'contextIsolation: false' },
      { re: /sandbox\s*:\s*false/g, name: 'sandbox: false' },
      { re: /webSecurity\s*:\s*false/g, name: 'webSecurity: false' },
      { re: /allowRunningInsecureContent\s*:\s*true/g, name: 'allowRunningInsecureContent: true' },
      { re: /webviewTag\s*:\s*true/g, name: 'webviewTag: true' },
      { re: /enableRemoteModule\s*:\s*true/g, name: 'enableRemoteModule: true' }
    ];

    for (const { re, name } of badPatterns) {
      let m;
      while ((m = re.exec(file.content))) {
        issues++;
        report.add({
          id: 'CODE-17',
          title: `Insecure Electron webPreferences: ${name}`,
          severity: 'critical',
          confidence: CONFIDENCE.CONFIRMED,
          where: `${file.rel}:${lineOf(file.content, m.index)}`,
          detail: `${name} breaks the Electron sandbox boundary, enabling XSS in the renderer to gain full OS/Node.js command execution privileges.`,
          remediation: 'Set contextIsolation: true, sandbox: true, nodeIntegration: false, webSecurity: true, allowRunningInsecureContent: false, and webviewTag: false.'
        });
      }
    }
  }

  if (!issues) report.pass('CODE-17', 'Electron process isolation and secure webPreferences verified');
}

/* ------------------------------------------------------------------------- *
 * CODE-18  Local listener network binding (localhost vs 0.0.0.0)
 * ------------------------------------------------------------------------- */
function checkLocalListeners(files, report) {
  const listenerFiles = files.filter(f => isScript(f) && /(?:net\.createServer|http\.createServer|https\.createServer)\b/.test(f.content));
  if (!listenerFiles.length) return;

  let issues = 0;
  for (const file of listenerFiles) {
    const openListen = /\.listen\s*\(\s*(?:options\.[A-Za-z0-9_]+|[0-9]+)\s*,\s*(?:\(\)|function|\(\s*err\s*\))/g;
    let m;
    while ((m = openListen.exec(file.content))) {
      issues++;
      report.add({
        id: 'CODE-18',
        title: 'Local server listener without explicit loopback address binding',
        severity: 'high',
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: 'Calling .listen(port) without an explicit host binds to 0.0.0.0 on all network interfaces, exposing local port forwarding or proxies to the entire local network / Wi-Fi.',
        remediation: "Explicitly pass '127.0.0.1' or '::1' as the host parameter: server.listen(port, '127.0.0.1', callback)."
      });
    }
  }

  if (!issues) report.pass('CODE-18', 'Local server listeners explicitly bind to loopback (127.0.0.1)');
}

/* ------------------------------------------------------------------------- *
 * CODE-19  Tauri open_external_url — unvalidated URL scheme (SSRF / Command Injection)
 *
 * Origin: k8sUI audit 2026-09-02. The `open_external_url` Tauri command accepted
 * any URL string and passed it directly to the OS `open` / `cmd /C start` /
 * `xdg-open` without scheme validation. A `file://` or `javascript:` URI, or a
 * shell-injectable string, could have been passed from an untrusted source.
 * Fix: allowlist only https:// and http:// before calling the OS opener.
 * ------------------------------------------------------------------------- */
function checkTauriOpenUrl(files, report) {
  // Only meaningful in Rust files
  const rustFiles = files.filter(f => f.ext === '.rs');
  if (!rustFiles.length) return;

  let issues = 0;
  for (const file of rustFiles) {
    // Look for functions that spawn an OS opener (open/xdg-open/cmd start)
    const spawnsOpener = /Command::new\s*\(\s*"(?:open|xdg-open|osascript)"\s*\)|args\s*\(&\s*\[.*"start"/.test(file.content);
    if (!spawnsOpener) continue;

    // Check whether a scheme guard exists in the same file
    const hasSchemeGuard = /starts_with\s*\(\s*"https?:\/\/"/.test(file.content) ||
                           /scheme_ok|allowed_scheme|url_scheme/.test(file.content);

    if (!hasSchemeGuard) {
      issues++;
      report.add({
        id: 'CODE-19',
        title: 'Tauri OS opener called without URL scheme validation',
        severity: 'high',
        confidence: 'likely',
        where: file.rel,
        detail: 'A Tauri command passes a URL string to an OS opener (open/xdg-open/cmd start) without validating the scheme. Passing file://, javascript: or a shell-injectable string is a command injection risk.',
        remediation: "Before calling the OS opener, assert the URL starts with 'https://' or 'http://'. Reject anything else with an error response.",
      });
    } else {
      report.pass('CODE-19', `${file.rel} validates URL scheme before OS opener`);
    }
  }
  if (!issues && !files.filter(f => f.ext === '.rs').length) {
    report.pass('CODE-19', 'No Rust OS-opener calls found');
  }
}

/* ------------------------------------------------------------------------- *
 * CODE-20  Hardcoded audit cluster IDs / environment labels in Rust commands
 *
 * Origin: k8sUI audit 2026-09-02. The `restart_resource` and `delete_resource`
 * Tauri commands wrote literal strings "active_cluster" and "Production" as the
 * cluster_id and environment in audit log entries. Operations on staging/local
 * clusters were falsely recorded as Production — an audit integrity bug.
 * Fix: resolve cluster ID/environment from session state dynamically.
 * ------------------------------------------------------------------------- */
function checkHardcodedAuditIds(files, report) {
  const rustFiles = files.filter(f => f.ext === '.rs');
  if (!rustFiles.length) return;

  // Patterns that indicate a literal placeholder ID inside an audit.log() call
  const HARDCODED_AUDIT_ID = /\.log\s*\(\s*"active_cluster"|\.log\s*\([^,]+,\s*"Production"/g;

  let issues = 0;
  for (const file of rustFiles) {
    HARDCODED_AUDIT_ID.lastIndex = 0;
    let m;
    while ((m = HARDCODED_AUDIT_ID.exec(file.content))) {
      issues++;
      report.add({
        id: 'CODE-20',
        title: 'Hardcoded literal cluster ID or environment in audit log call',
        severity: 'medium',
        confidence: 'confirmed',
        where: `${file.rel}:${lineOf(file.content, m.index)}`,
        detail: 'The audit log entry uses a literal string ("active_cluster" or "Production") instead of the real cluster ID or environment resolved from session state. Mutations on non-production clusters will be mislabelled in audit records.',
        remediation: 'Resolve the cluster ID and environment from the session manager (e.g. get_active_summary()) and pass real values to the audit logger.',
      });
    }
  }
  if (!issues) report.pass('CODE-20', 'No hardcoded audit cluster IDs or environment labels found');
}

/* ------------------------------------------------------------------------- *
 * CODE-21  Tauri capability: shell:default is overly broad
 *
 * Origin: k8sUI audit 2026-09-02. The capabilities/default.json granted
 * `shell:default` which includes both `open` (URL opener) and `execute`
 * (arbitrary process spawner). Only `shell:allow-open` is needed for external
 * URL handling. `shell:default` gives the frontend JavaScript the ability to
 * execute arbitrary shell commands via Tauri IPC.
 * ------------------------------------------------------------------------- */
function checkTauriShellCapability(files, report) {
  const capFiles = files.filter(f => /capabilities[/\\]/.test(f.rel) && f.ext === '.json');
  if (!capFiles.length) return;

  let issues = 0;
  for (const file of capFiles) {
    let parsed;
    try { parsed = JSON.parse(file.content); } catch { continue; }

    const permissions = Array.isArray(parsed.permissions) ? parsed.permissions : [];
    if (permissions.includes('shell:default') || permissions.includes('shell:all')) {
      issues++;
      report.add({
        id: 'CODE-21',
        title: 'Tauri capability grants shell:default (includes process execute)',
        severity: 'high',
        confidence: 'confirmed',
        where: file.rel,
        detail: '"shell:default" grants the frontend both the open API (safe) and the execute API (dangerous). A single compromised dependency can invoke arbitrary OS processes via Tauri IPC.',
        remediation: 'Replace "shell:default" with "shell:allow-open" to restrict the shell plugin to URL/file opening only, removing the arbitrary process execution surface.',
      });
    } else {
      report.pass('CODE-21', `${file.rel} does not grant overly broad shell:default`);
    }
  }
}

/* ------------------------------------------------------------------------- *
 * CODE-22  Tauri CSP must not be null or omitted
 *
 * Origin: k8sUI best-practice baseline. The tauri.conf.json CSP field defaults
 * to null in new projects, meaning the WebView has no content restriction.
 * A null CSP lets any injected script exfiltrate data to arbitrary remote hosts.
 * ------------------------------------------------------------------------- */
function checkTauriCsp(files, report) {
  const confFiles = files.filter(f => /tauri\.conf\.json$/.test(f.rel));
  if (!confFiles.length) return;

  for (const file of confFiles) {
    let parsed;
    try { parsed = JSON.parse(file.content); } catch { continue; }

    // Navigate to security.csp (Tauri v2 schema path)
    const csp = parsed?.app?.security?.csp ?? parsed?.tauri?.security?.csp ?? null;

    if (csp === null || csp === undefined || csp === '') {
      report.add({
        id: 'CODE-22',
        title: 'Tauri tauri.conf.json has no Content-Security-Policy (CSP)',
        severity: 'high',
        confidence: 'confirmed',
        where: file.rel,
        detail: 'The CSP field is null or absent. Without a CSP the Tauri WebView imposes no restriction on script sources or network destinations, so a successful script injection can exfiltrate cluster data to any host.',
        remediation: "Set a strict CSP in tauri.conf.json: \"csp\": \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'\".",
      });
    } else {
      const weak = [];
      const cspStr = String(csp);
      if (/script-src[^;]*'unsafe-inline'/.test(cspStr)) weak.push("script-src allows 'unsafe-inline'");
      if (/script-src[^;]*'unsafe-eval'/.test(cspStr)) weak.push("script-src allows 'unsafe-eval'");
      if (!/object-src/.test(cspStr)) weak.push("object-src is unset");
      if (!/base-uri/.test(cspStr)) weak.push("base-uri is unset");

      if (weak.length) {
        report.add({
          id: 'CODE-22',
          title: 'Tauri CSP is weaker than recommended',
          severity: 'medium',
          confidence: 'confirmed',
          where: file.rel,
          detail: weak.join('; ') + '.',
          remediation: "Tighten the CSP: remove 'unsafe-inline'/'unsafe-eval', set object-src 'none', set base-uri 'none'.",
        });
      } else {
        report.pass('CODE-22', `${file.rel} has a Tauri CSP with no obvious weakness`);
      }
    }
  }
}

/* ------------------------------------------------------------------------- */

function runCodeChecks(root, report) {
  const files = readTextFiles(root);
  if (!files.length) throw new Error(`No readable source files under ${root}`);
  report.scanned = files.length;

  checkHtmlSinks(files, report);
  checkEscapeHelper(files, report);
  checkSecrets(files, report);
  checkSsrf(files, report);
  checkCors(files, report);
  checkIneffectiveMeta(files, report);
  checkCsp(files, report);
  checkPublishSurface(files, report);
  checkCiHygiene(files, report);
  checkDangerousApis(files, report);
  checkWebStorage(files, report);
  checkPathTraversal(files, report);
  checkDependencies(root, files, report);
  checkTransportAndLinks(files, report);
  checkElectronSecurity(files, report);
  checkLocalListeners(files, report);
  // Tauri / Rust desktop application checks (from k8sUI audit 2026-09-02)
  checkTauriOpenUrl(files, report);
  checkHardcodedAuditIds(files, report);
  checkTauriShellCapability(files, report);
  checkTauriCsp(files, report);

  return report;
}

module.exports = { runCodeChecks };
