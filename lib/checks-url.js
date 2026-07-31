'use strict';

/**
 * Runtime checks against a deployed URL.
 *
 * Deliberately non-invasive. Every request is a plain GET/HEAD for a path that a
 * normal client could request; there is no fuzzing, no payload injection and no
 * port scanning. The point is to observe how the origin is configured, which is
 * exactly what the static scanner cannot see — a header set at the CDN is
 * invisible in the repo, and a header written as a meta tag looks present in the
 * repo while being absent on the wire.
 *
 * Only run this against properties your organisation controls.
 */

const tls = require('tls');
const { CONFIDENCE } = require('./report');
const { metaContent } = require('./walk');
const { findSecrets } = require('./secrets');

const UA = 'akretrix-securitytests/1.0 (internal configuration review)';
const TIMEOUT_MS = 12000;

async function get(url, { method = 'GET', headers = {}, redirect = 'manual' } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method,
      redirect,
      headers: { 'user-agent': UA, ...headers },
      signal: controller.signal,
    });
    const body = method === 'HEAD' ? '' : await res.text().catch(() => '');
    return { status: res.status, headers: res.headers, body, url: res.url };
  } finally {
    clearTimeout(timer);
  }
}

/* ------------------------------------------------------------------------- *
 * URL-01  Security headers actually present on the wire
 *
 * Origin: the repo carried <meta http-equiv="X-Content-Type-Options">, which
 * browsers ignore. Only a live request can tell you whether the protection is
 * real, which is why this check exists separately from CODE-06.
 * ------------------------------------------------------------------------- */
const REQUIRED_HEADERS = [
  {
    name: 'content-security-policy',
    severity: 'high',
    why: 'Without a CSP, one HTML injection runs with full privileges and can exfiltrate anywhere.',
    metaFallbackOk: true,
  },
  {
    name: 'x-content-type-options',
    severity: 'medium',
    why: 'Without nosniff, a browser may re-interpret an uploaded or user-controlled file as HTML or script.',
  },
  {
    name: 'referrer-policy',
    severity: 'low',
    why: 'Full URLs leak to third parties in the Referer header.',
    metaFallbackOk: true,
  },
  {
    name: 'strict-transport-security',
    severity: 'high',
    why: 'Without HSTS the first request can be downgraded to http:// and intercepted.',
    httpsOnly: true,
  },
  {
    name: 'x-frame-options',
    severity: 'medium',
    why: 'Without framing protection the page can be embedded and clickjacked.',
    satisfiedBy: csp => /frame-ancestors/.test(csp || ''),
    satisfiedNote: "CSP frame-ancestors is present, which supersedes X-Frame-Options",
  },
];

function checkHeaders(res, url, report) {
  const isHttps = url.startsWith('https://');
  const csp = res.headers.get('content-security-policy');

  for (const h of REQUIRED_HEADERS) {
    if (h.httpsOnly && !isHttps) continue;
    const value = res.headers.get(h.name);
    if (value) {
      report.pass('URL-01', `${h.name}: ${value.slice(0, 70)}`);
      continue;
    }
    if (h.satisfiedBy && h.satisfiedBy(csp)) {
      report.pass('URL-01', `${h.name} not needed — ${h.satisfiedNote}`);
      continue;
    }

    /* For the two directives a meta tag can legitimately carry, check the
       document before calling this a gap. Reporting a served CSP as "missing"
       at high severity trains people to ignore the scanner. */
    if (h.metaFallbackOk) {
      const metaName = h.name === 'content-security-policy' ? 'Content-Security-Policy' : 'Referrer-Policy';
      const viaMeta = metaContent(res.body || '', metaName)
        || (metaName === 'Referrer-Policy' && /<meta\s+name=["']referrer["']/i.test(res.body || '') ? 'set via <meta name="referrer">' : null);
      if (viaMeta) {
        report.add({
          id: 'URL-01',
          title: `"${h.name}" is delivered by a meta tag rather than a header`,
          severity: 'low',
          where: url,
          detail: `Browsers honour this directive from meta, so the protection is real. It still only applies to HTML documents — a header additionally covers JSON, SVG and other non-HTML responses, and applies before the document is parsed.`,
          remediation: 'Promote it to a response header at the CDN; keep the meta tag as a fallback.',
        });
        continue;
      }
    }

    report.add({
      id: 'URL-01',
      title: `Response header "${h.name}" is missing`,
      severity: h.severity,
      where: url,
      detail: h.why + (h.metaFallbackOk ? '' : ' This header cannot be set from a meta tag — it must come from the CDN or origin.'),
      remediation: 'Attach it with a CloudFront response-headers policy (or equivalent) on the default cache behaviour.',
    });
  }
}

/* URL-02  HSTS quality */
function checkHsts(res, url, report) {
  const hsts = res.headers.get('strict-transport-security');
  if (!hsts) return;
  const maxAge = /max-age=(\d+)/i.exec(hsts);
  const seconds = maxAge ? Number(maxAge[1]) : 0;
  const problems = [];
  if (seconds < 15768000) problems.push(`max-age is ${seconds}s; at least 15768000 (6 months) is expected`);
  if (!/includeSubDomains/i.test(hsts)) problems.push('includeSubDomains is absent, so subdomains stay downgradable');
  if (problems.length) {
    report.add({
      id: 'URL-02',
      title: 'HSTS is present but weak',
      severity: 'low',
      where: url,
      detail: problems.join('; ') + '.',
      remediation: 'Set max-age=31536000; includeSubDomains, and consider preload once you are certain every subdomain serves HTTPS.',
    });
  } else {
    report.pass('URL-02', 'HSTS max-age and includeSubDomains are adequate');
  }
}

/* URL-03  CSP quality on the wire */
function checkCspRuntime(res, url, report) {
  const csp = res.headers.get('content-security-policy')
    || metaContent(res.body || '', 'Content-Security-Policy');
  if (!csp) return;
  const weak = [];
  if (/script-src[^;]*'unsafe-inline'/.test(csp)) weak.push("script-src allows 'unsafe-inline'");
  if (/script-src[^;]*'unsafe-eval'/.test(csp)) weak.push("script-src allows 'unsafe-eval'");
  if (!/object-src/.test(csp)) weak.push("object-src unset");
  if (!/base-uri/.test(csp)) weak.push('base-uri unset');
  if (!/frame-ancestors/.test(csp) && !res.headers.get('x-frame-options')) weak.push('frame-ancestors unset and no X-Frame-Options');
  if (weak.length) {
    report.add({
      id: 'URL-03',
      title: 'CSP is served but leaves gaps',
      severity: 'low',
      where: url,
      detail: weak.join('; ') + '.',
      remediation: "Externalise inline scripts to drop 'unsafe-inline', and set object-src/base-uri to 'none'. Note frame-ancestors only works as a header, never from meta.",
    });
  } else {
    report.pass('URL-03', 'Served CSP has no obvious weakness');
  }
}

/* URL-04  HTTPS enforcement */
async function checkHttpsRedirect(url, report) {
  if (!url.startsWith('https://')) {
    report.add({
      id: 'URL-04',
      title: 'Target was scanned over plaintext HTTP',
      severity: 'high',
      where: url,
      detail: 'Traffic is readable and modifiable in transit.',
      remediation: 'Serve the site over HTTPS only and redirect http:// to https://.',
    });
    return;
  }
  const httpUrl = url.replace(/^https:/, 'http:');
  try {
    const res = await get(httpUrl, { redirect: 'manual' });
    const location = res.headers.get('location') || '';
    if (res.status >= 300 && res.status < 400 && location.startsWith('https://')) {
      report.pass('URL-04', `http:// redirects to HTTPS (${res.status})`);
    } else if (res.status >= 300 && res.status < 400) {
      report.add({
        id: 'URL-04',
        title: 'Plaintext HTTP redirects somewhere other than HTTPS',
        severity: 'medium',
        where: httpUrl,
        detail: `Status ${res.status} to "${location || '(no Location)'}".`,
        remediation: 'Redirect straight to the https:// equivalent of the same path.',
      });
    } else {
      report.add({
        id: 'URL-04',
        title: 'Plaintext HTTP is served without redirecting to HTTPS',
        severity: 'high',
        where: httpUrl,
        detail: `Status ${res.status} — the site answers over http://, so a downgrade is possible.`,
        remediation: 'Force a redirect to HTTPS at the CDN and enable HSTS.',
      });
    }
  } catch {
    report.pass('URL-04', 'Plaintext HTTP is not reachable');
  }
}

/* URL-05  TLS protocol, cipher and certificate window */
function inspectTls(hostname, port) {
  return new Promise(resolve => {
    let settled = false;
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, timeout: TIMEOUT_MS, ALPNProtocols: ['h2', 'http/1.1'] },
      () => {
        if (settled) return;
        settled = true;
        const cert = socket.getPeerCertificate();
        const info = {
          protocol: socket.getProtocol(),
          cipher: socket.getCipher(),
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          validTo: cert && cert.valid_to ? cert.valid_to : null,
          issuer: cert && cert.issuer ? cert.issuer.CN : null,
        };
        socket.end();
        resolve(info);
      }
    );
    socket.on('timeout', () => { if (!settled) { settled = true; socket.destroy(); resolve({ error: 'TLS handshake timed out' }); } });
    socket.on('error', e => { if (!settled) { settled = true; resolve({ error: e.message }); } });
  });
}

async function checkTls(target, report) {
  if (target.protocol !== 'https:') return;
  const port = target.port ? Number(target.port) : 443;
  const info = await inspectTls(target.hostname, port);
  if (info.error) {
    report.add({
      id: 'URL-05',
      title: 'Could not complete a TLS handshake',
      severity: 'medium',
      where: `${target.hostname}:${port}`,
      detail: info.error,
      remediation: 'Confirm the certificate and listener are healthy.',
    });
    return;
  }
  if (!info.authorized) {
    report.add({
      id: 'URL-05',
      title: 'Certificate did not validate',
      severity: 'critical',
      where: target.hostname,
      detail: `${info.authorizationError || 'unknown validation error'} (issuer: ${info.issuer || 'unknown'}).`,
      remediation: 'Install a certificate that chains to a public root and matches the hostname.',
    });
  }
  if (/TLSv1(\.[01])?$/.test(info.protocol || '')) {
    report.add({
      id: 'URL-05',
      title: `Obsolete TLS version negotiated (${info.protocol})`,
      severity: 'high',
      where: target.hostname,
      detail: 'TLS 1.0/1.1 are deprecated and fail modern compliance baselines.',
      remediation: 'Require TLS 1.2 as a minimum; prefer 1.3.',
    });
  }
  if (info.validTo) {
    const daysLeft = Math.floor((Date.parse(info.validTo) - Date.now()) / 86400000);
    if (daysLeft < 0) {
      report.add({ id: 'URL-05', title: 'Certificate has expired', severity: 'critical', where: target.hostname, detail: `Expired ${-daysLeft} day(s) ago (${info.validTo}).`, remediation: 'Renew immediately.' });
    } else if (daysLeft < 21) {
      report.add({ id: 'URL-05', title: `Certificate expires in ${daysLeft} day(s)`, severity: 'medium', where: target.hostname, detail: `Not after ${info.validTo}.`, remediation: 'Confirm automated renewal is working.' });
    } else {
      report.pass('URL-05', `TLS ${info.protocol}, ${info.cipher && info.cipher.name}, cert valid ${daysLeft} more day(s)`);
    }
  }
}

/* URL-06  Cookie flags */
function checkCookies(res, url, report) {
  const raw = typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie()
    : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
  if (!raw.length) {
    report.pass('URL-06', 'No cookies set on this response');
    return;
  }
  for (const cookie of raw) {
    const name = cookie.split('=')[0];
    const missing = [];
    if (!/;\s*Secure/i.test(cookie)) missing.push('Secure');
    if (!/;\s*HttpOnly/i.test(cookie)) missing.push('HttpOnly');
    if (!/;\s*SameSite=/i.test(cookie)) missing.push('SameSite');
    if (missing.length) {
      report.add({
        id: 'URL-06',
        title: `Cookie "${name}" is missing ${missing.join(', ')}`,
        severity: missing.includes('HttpOnly') || missing.includes('Secure') ? 'high' : 'medium',
        where: url,
        detail: 'Without Secure it can travel in plaintext; without HttpOnly any XSS can read it; without SameSite it rides cross-site requests.',
        remediation: 'Set Secure; HttpOnly; SameSite=Lax (or Strict) on every session cookie.',
      });
    } else {
      report.pass('URL-06', `Cookie "${name}" sets Secure, HttpOnly and SameSite`);
    }
  }
}

/* URL-07  Version banners */
function checkBanners(res, url, report) {
  for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) {
    const value = res.headers.get(name);
    if (!value) continue;
    const revealsVersion = /\d+\.\d+/.test(value);
    report.add({
      id: 'URL-07',
      title: `"${name}" header advertises the stack${revealsVersion ? ' and its version' : ''}`,
      severity: revealsVersion ? 'low' : 'info',
      where: url,
      detail: `${name}: ${value}`,
      remediation: 'Strip or generalise the banner so scanners cannot match a known CVE to a version.',
    });
  }
}

/* ------------------------------------------------------------------------- *
 * URL-08  Files that should never be publicly reachable
 *
 * Origin: the deploy synced the repository root to a public bucket, so dev
 * config and internal notes were published. This is the live counterpart to
 * CODE-08 — it verifies what is actually being served, not what the workflow
 * intended.
 * ------------------------------------------------------------------------- */
const SENSITIVE_PATHS = [
  { p: '/.git/config', sev: 'critical', why: 'Exposes the full repository, including history and any secret ever committed.' },
  { p: '/.git/HEAD', sev: 'critical', why: 'Indicates a served .git directory.' },
  { p: '/.env', sev: 'critical', why: 'Environment files hold credentials.' },
  { p: '/.env.local', sev: 'critical', why: 'Environment files hold credentials.' },
  { p: '/.claude/settings.local.json', sev: 'medium', why: 'Local tooling config was published by an over-broad deploy.' },
  { p: '/.DS_Store', sev: 'low', why: 'Leaks directory listings.' },
  { p: '/package.json', sev: 'low', why: 'Reveals dependencies and versions to match against advisories.' },
  { p: '/package-lock.json', sev: 'low', why: 'Reveals the full dependency tree.' },
  { p: '/AGENTS.md', sev: 'low', why: 'Internal engineering notes.' },
  { p: '/README.md', sev: 'info', why: 'Often intentional, but it does describe your infrastructure.' },
  { p: '/serve-local.js', sev: 'low', why: 'Development-only server script.' },
  { p: '/backend/template.yaml', sev: 'medium', why: 'Infrastructure definition discloses architecture and parameters.' },
];

async function checkExposedPaths(origin, report) {
  let exposed = 0;
  for (const { p, sev, why } of SENSITIVE_PATHS) {
    let res;
    try {
      res = await get(origin + p, { redirect: 'manual' });
    } catch {
      continue;
    }
    if (res.status !== 200) continue;

    // A SPA that rewrites every unknown path to index.html would otherwise
    // report all of these as exposed. Treat an HTML body for a non-HTML path
    // as the catch-all, not the real file.
    const looksLikeHtmlFallback = /^\s*<(?:!doctype|html)/i.test(res.body || '') && !p.endsWith('.md');
    if (looksLikeHtmlFallback) continue;

    exposed++;
    report.add({
      id: 'URL-08',
      title: `Sensitive path is publicly reachable: ${p}`,
      severity: sev,
      where: origin + p,
      detail: `${why} Returned 200 with ${(res.body || '').length} bytes.`,
      remediation: 'Publish only the built site directory, and confirm the bucket/CDN cannot serve dotfiles.',
    });
  }
  if (!exposed) report.pass('URL-08', `None of the ${SENSITIVE_PATHS.length} sensitive paths are reachable`);
}

/* URL-09  Directory listing */
async function checkDirectoryListing(origin, report) {
  for (const dir of ['/assets/', '/tools/', '/js/', '/css/']) {
    let res;
    try {
      res = await get(origin + dir, { redirect: 'manual' });
    } catch {
      continue;
    }
    if (res.status !== 200) continue;
    if (/Index of\s*\/|<title>Directory listing/i.test(res.body || '')) {
      report.add({
        id: 'URL-09',
        title: `Directory listing is enabled at ${dir}`,
        severity: 'medium',
        where: origin + dir,
        detail: 'Enumerable directories reveal files that were never meant to be discovered.',
        remediation: 'Disable autoindex, and return the 404 document for directory paths.',
      });
    }
  }
  report.pass('URL-09', 'No directory listings detected on common asset paths');
}

/* ------------------------------------------------------------------------- *
 * URL-10  CORS reflection
 *
 * Origin: the API defaulted Access-Control-Allow-Origin to "*". A live probe is
 * the only way to catch the case where a deploy shipped without its origin set.
 * ------------------------------------------------------------------------- */
async function checkCorsReflection(url, report) {
  const probe = 'https://not-your-origin.example';
  let res;
  try {
    res = await get(url, { headers: { origin: probe }, redirect: 'manual' });
  } catch {
    return;
  }
  const allow = res.headers.get('access-control-allow-origin');
  const credentials = res.headers.get('access-control-allow-credentials');
  if (!allow) {
    report.pass('URL-10', 'No Access-Control-Allow-Origin returned for a foreign Origin');
    return;
  }
  if (allow === '*') {
    report.add({
      id: 'URL-10',
      title: 'Access-Control-Allow-Origin is "*"',
      severity: credentials === 'true' ? 'critical' : 'medium',
      where: url,
      detail: credentials === 'true'
        ? 'Wildcard origin combined with Allow-Credentials lets any site read authenticated responses.'
        : 'Any website can read responses from this endpoint via a visitor\'s browser.',
      remediation: 'Return a single explicit origin, and omit the header entirely when unconfigured.',
    });
  } else if (allow === probe) {
    report.add({
      id: 'URL-10',
      title: 'Access-Control-Allow-Origin reflects any supplied Origin',
      severity: 'high',
      where: url,
      detail: `Sent Origin: ${probe} and it was echoed back, which is equivalent to a wildcard while also working with credentials.`,
      remediation: 'Compare the Origin against an allow-list and echo it only on a match.',
    });
  } else {
    report.pass('URL-10', `Access-Control-Allow-Origin is pinned to ${allow}`);
  }
}

/* URL-11  Mixed content in the delivered HTML */
function checkMixedContent(res, url, report) {
  if (!url.startsWith('https://')) return;
  const found = [...(res.body || '').matchAll(/(?:src|href)=["']http:\/\/(?!localhost|127\.0\.0\.1)([^"']+)["']/g)];
  if (!found.length) {
    report.pass('URL-11', 'No plaintext subresources in the delivered HTML');
    return;
  }
  report.add({
    id: 'URL-11',
    title: `Delivered HTML references ${found.length} plaintext http:// resource(s)`,
    severity: 'medium',
    where: url,
    detail: found.slice(0, 4).map(m => 'http://' + m[1].slice(0, 50)).join(', '),
    remediation: 'Switch to https:// or root-relative URLs.',
  });
}

/* ------------------------------------------------------------------------- *
 * URL-13  Credentials exposed in delivered assets
 *
 * The static scanner answers "is a credential committed?". This answers the
 * question that actually determines impact: "is one being handed to every
 * visitor?" They are not the same. A build step can inline a server-side
 * environment variable into a bundle, a deploy can publish a file that was never
 * meant to ship, and a sourcemap can expose original source that the minified
 * output hid — none of which the repo scan sees.
 * ------------------------------------------------------------------------- */
const MAX_ASSETS = 20;
const MAX_ASSET_BYTES = 3 * 1024 * 1024;

/** Same-origin script/style/preload URLs referenced by the document. */
function sameOriginAssets(html, origin) {
  const urls = new Set();
  const attrRe = /(?:src|href)=["']([^"']+)["']/gi;
  let m;
  while ((m = attrRe.exec(html))) {
    const raw = m[1];
    if (!/\.(?:js|mjs|css|json|map)(?:\?|$)/i.test(raw)) continue;
    let abs;
    try {
      abs = new URL(raw, origin);
    } catch {
      continue;
    }
    // Third-party assets are not ours to audit and may be large.
    if (abs.origin !== new URL(origin).origin) continue;
    urls.add(abs.toString());
    if (urls.size >= MAX_ASSETS) break;
  }
  return [...urls];
}

async function checkExposedCredentials(res, target, report) {
  const origin = target.origin;
  const documents = [{ label: target.toString(), text: res.body || '' }];

  const assets = sameOriginAssets(res.body || '', origin);
  for (const url of assets) {
    try {
      const asset = await get(url, { redirect: 'follow' });
      if (asset.status !== 200) continue;
      const text = (asset.body || '').slice(0, MAX_ASSET_BYTES);
      documents.push({ label: url, text });
    } catch {
      /* unreachable asset is not a credential finding */
    }
  }

  let found = 0;
  for (const doc of documents) {
    for (const hit of findSecrets(doc.text)) {
      found++;
      report.add({
        id: 'URL-13',
        title: `${hit.what} is being served to the public`,
        severity: hit.severity === 'critical' ? 'critical' : 'high',
        confidence: CONFIDENCE.LIKELY,
        where: doc.label,
        // Redacted: this report is a CI artefact, so printing the value in full
        // would make the report itself another copy of the exposed credential.
        detail: `Matched ${hit.what}: ${hit.redacted}. Anyone who loads this URL has it. Treat it as compromised — it cannot be un-served.`,
        remediation: 'Rotate the credential immediately, then remove it from the published asset. If a build inlined it, the value must move server-side.',
      });
    }
  }

  /* A sourcemap republishes the original, unminified source — including comments
     and any string a minifier would otherwise have obscured. */
  const maps = assets.filter(u => /\.map(?:\?|$)/i.test(u));
  for (const scriptUrl of assets.filter(u => /\.(?:js|mjs|css)(?:\?|$)/i.test(u)).slice(0, 6)) {
    const guess = scriptUrl.replace(/(\?.*)?$/, '') + '.map';
    if (maps.includes(guess)) continue;
    try {
      const probe = await get(guess, { redirect: 'manual' });
      if (probe.status === 200 && /"(?:sources|mappings)"\s*:/.test(probe.body || '')) {
        report.add({
          id: 'URL-13',
          title: 'Sourcemap is publicly reachable',
          severity: 'low',
          where: guess,
          detail: 'Republishes the original source, including comments and strings that the shipped build would otherwise obscure.',
          remediation: 'Stop deploying .map files, or restrict them at the CDN.',
        });
      }
    } catch {
      /* absent is the expected case */
    }
  }

  if (!found) {
    report.pass('URL-13', `No credentials found across ${documents.length} delivered asset(s)`);
  }
}

/* URL-12  HTML caching */
function checkHtmlCaching(res, url, report) {
  const cc = res.headers.get('cache-control') || '';
  const type = res.headers.get('content-type') || '';
  if (!/text\/html/.test(type)) return;
  const maxAge = /max-age=(\d+)/.exec(cc);
  if (!cc || (maxAge && Number(maxAge[1]) > 3600)) {
    report.add({
      id: 'URL-12',
      title: 'HTML is cached for a long time (or has no Cache-Control)',
      severity: 'low',
      where: url,
      detail: `Cache-Control: ${cc || '(absent)'}. Visitors can keep running an old page — including a version whose vulnerability you have already fixed.`,
      remediation: 'Serve HTML with no-cache and let fingerprinted assets carry the long max-age.',
    });
  } else {
    report.pass('URL-12', `HTML caching is conservative (${cc})`);
  }
}

/* ------------------------------------------------------------------------- */

async function runUrlChecks(rawUrl, report) {
  const target = new URL(rawUrl);
  const origin = target.origin;

  const res = await get(target.toString(), { redirect: 'follow' });
  report.status = res.status;

  checkHeaders(res, target.toString(), report);
  checkHsts(res, target.toString(), report);
  checkCspRuntime(res, target.toString(), report);
  checkCookies(res, target.toString(), report);
  checkBanners(res, target.toString(), report);
  checkMixedContent(res, target.toString(), report);
  checkHtmlCaching(res, target.toString(), report);

  await checkHttpsRedirect(target.toString(), report);
  await checkTls(target, report);
  await checkExposedPaths(origin, report);
  await checkDirectoryListing(origin, report);
  await checkCorsReflection(target.toString(), report);
  await checkExposedCredentials(res, target, report);

  return report;
}

module.exports = { runUrlChecks };
