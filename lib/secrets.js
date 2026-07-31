'use strict';

/**
 * Credential detection, shared by every mode.
 *
 * One list on purpose. The static scanner asks "is a credential committed?" and
 * the runtime scanners ask "is a credential being served to the public?" — the
 * same patterns answer both, and a pattern added for one immediately protects the
 * other. Keeping two lists guarantees they drift.
 */

const PATTERNS = [
  { re: /AKIA[0-9A-Z]{16}/g, what: 'AWS access key id', severity: 'critical' },
  { re: /ASIA[0-9A-Z]{16}/g, what: 'AWS temporary access key id', severity: 'critical' },
  { re: /aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}/gi, what: 'AWS secret access key', severity: 'critical' },
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, what: 'private key', severity: 'critical' },
  { re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, what: 'Slack token', severity: 'critical' },
  { re: /gh[pousr]_[A-Za-z0-9]{20,}/g, what: 'GitHub token', severity: 'critical' },
  { re: /glpat-[A-Za-z0-9_-]{20,}/g, what: 'GitLab token', severity: 'critical' },
  { re: /sk-ant-[A-Za-z0-9_-]{20,}/g, what: 'Anthropic API key', severity: 'critical' },
  { re: /sk-[A-Za-z0-9]{32,}/g, what: 'OpenAI-style API key', severity: 'critical' },
  { re: /sk_live_[A-Za-z0-9]{16,}/g, what: 'Stripe live secret key', severity: 'critical' },
  { re: /rk_live_[A-Za-z0-9]{16,}/g, what: 'Stripe live restricted key', severity: 'critical' },
  { re: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, what: 'SendGrid API key', severity: 'critical' },
  { re: /AIza[0-9A-Za-z_-]{35}/g, what: 'Google API key', severity: 'high' },
  { re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, what: 'JWT', severity: 'high' },
  { re: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s:@/]+@/gi, what: 'connection string with inline credentials', severity: 'critical' },
  /* Cloudflare Turnstile: a SITEKEY is public by design and belongs in the page,
     while a SECRET key must never leave the server — and both share the 0x4A…
     prefix, so they are trivially confused. Flagged wherever a value of this
     shape appears next to secret-ish wording, since shape alone cannot tell them
     apart. */
  { re: /turnstile[_-]?secret[_-]?key["'\s:=]+0x4[A-Za-z0-9_-]{20,}/gi, what: 'Cloudflare Turnstile SECRET key', severity: 'critical' },
  { re: /(?:secret|private|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token)["'\s:=]+['"][A-Za-z0-9_\-/+=]{20,}['"]/gi, what: 'hardcoded secret-shaped assignment', severity: 'high' },
];

/**
 * Values that look like credentials but are published deliberately.
 *
 * Suppressing these is not leniency — a scanner that fires on every standard
 * local dev setup gets muted wholesale, which costs far more than these findings
 * are worth.
 */
function isKnownPublicTestCredential(match) {
  // Supabase local demo keys, byte-identical everywhere and loopback-only.
  if (/^eyJ/.test(match)) {
    try {
      const payload = match.split('.')[1];
      const decoded = Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
      if (/"iss"\s*:\s*"supabase-demo"/.test(decoded)) return true;
    } catch { /* undecodable — treat as real */ }
  }
  // Vendor-published test-mode prefixes.
  if (/^sk[-_](?:test|example)/i.test(match)) return true;
  // Cloudflare Turnstile dummy keys (1x…/2x…/3x… all-zero bodies).
  if (/^[123]x0{10,}[A-Z]{2}$/.test(match)) return true;
  return false;
}

/**
 * Obvious documentation stand-ins.
 *
 * Only explicit textual markers. Earlier versions also suppressed anything
 * containing "1234567890ABC" or a run of x's, which silently hid real values:
 * "AKIA1234567890ABCDEF" and a Google key containing "…1234567890abc…" both went
 * undetected. In a credential scanner a false negative is far worse than noise,
 * so a suppression rule has to be unambiguous — a random key can coincidentally
 * contain digits, but it will not contain the word PLACEHOLDER.
 */
function isPlaceholder(match) {
  return /YOUR[_-]|EXAMPLE|PLACEHOLDER|CHANGE[_-]?ME|REDACTED|DUMMY|FAKE|SAMPLE|<[a-z_-]+>/i.test(match);
}

/**
 * Finds credentials in a blob of text.
 * Returns [{ what, severity, match, index, redacted }].
 */
function findSecrets(text) {
  const hits = [];
  if (!text) return hits;
  for (const { re, what, severity } of PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      const value = m[0];
      if (isPlaceholder(value) || isKnownPublicTestCredential(value)) continue;
      hits.push({ what, severity, match: value, index: m.index, redacted: redact(value) });
    }
  }
  return hits;
}

/**
 * Shows enough to locate the value without reprinting it in full.
 *
 * A report is an artefact — it gets pasted into tickets and uploaded to CI. A
 * scanner that echoes the full credential turns its own output into a second
 * place the secret is exposed.
 */
function redact(value) {
  if (value.length <= 12) return value.slice(0, 4) + '…';
  return `${value.slice(0, 8)}…${value.slice(-4)} (${value.length} chars)`;
}

module.exports = { PATTERNS, findSecrets, redact, isKnownPublicTestCredential, isPlaceholder };
