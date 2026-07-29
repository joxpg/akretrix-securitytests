# AkreTrix Security Tests

Security tests every AkreTrix frontend must pass before it ships, and the tool
that runs them.

Two modes, because they catch different things and neither is sufficient alone:

| Mode | Input | Answers |
| :--- | :--- | :--- |
| `code` | a local path | *Is the source written safely?* Escaping, SSRF containment, secrets, CI and publish surface. |
| `url` | a deployed URL | *Is the environment configured safely?* Real response headers, TLS, cookies, exposed files, CORS. |

The split matters. A header written as `<meta http-equiv="X-Content-Type-Options">`
looks present in the repo and is silently ignored by every browser — only the
`url` mode sees that. Conversely an XSS sink is invisible from outside — only the
`code` mode sees that. **Run both.**

No dependencies. Node 18 or newer.

```bash
node bin/akretrix-sec.js code ../akretrix-landing-page
node bin/akretrix-sec.js url https://akretrix.com
```

> Run `url` mode only against properties your organisation controls. Every
> request it makes is a plain GET a normal browser could make — no fuzzing, no
> payloads, no port scanning — but pointing scanners at third parties is not
> yours to authorise.

---

## Usage

```
akretrix-sec code <path> [options]
akretrix-sec url  <url>  [options]

--json                 Machine-readable output, for CI artefacts
--fail-on <severity>   Exit 1 when a finding at or above this level exists
                       critical | high | medium | low | info | never
                       Default: high
--show-passed          Also list what passed
```

Exit codes: `0` clean (below threshold), `1` findings at or above threshold,
`2` the tool itself could not run. Wire `1` to a failing build and `2` to a
broken pipeline — they are not the same problem.

### Confidence

Static analysis cannot prove that a value reaching `innerHTML` is
attacker-controlled; that needs a human. Findings are therefore tagged:

- **confirmed** — true as written (a meta tag is present; a wildcard is set)
- **likely** — strong signal, small chance of a false positive
- **review** — a human must judge it; reported so it is not missed

`CODE-01` is deliberately `review`. It will flag interpolation of
developer-controlled constants alongside genuine remote data, because it cannot
tell them apart. Triage it; do not silence it.

---

## What gets tested

### A. Code evaluation — `akretrix-sec code <path>`

| ID | Check | Severity | Why it exists |
| :--- | :--- | :--- | :--- |
| CODE-01 | Unescaped values reaching `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `document.write` | high | Two DNS tools interpolated DNS record values into `innerHTML`. A TXT record is arbitrary attacker text, so looking up a hostile domain executed its markup. **Proven exploitable.** |
| CODE-02 | Escaping helper covers `& < > " '` | high / low | A shipped `escapeHtml()` omitted quotes — safe in text position, unsafe the moment a value lands in an attribute. |
| CODE-03 | Committed credentials (AWS, private keys, Slack/GitHub/OpenAI/Anthropic tokens, JWTs, DB URLs) | critical | Anything committed is disclosed permanently; git history keeps it after deletion. |
| CODE-04 | Outbound requests built from request input without full SSRF containment | critical | A Lambda dialled any host/port/URL from an unauthenticated query string. Requires **both** an IP-literal rejection and validation inside the connection's DNS lookup. |
| CODE-05 | Permissive or fail-open CORS (`\|\| '*'`, `Default: "*"`) | high | The API fell back to `*` when its env var was unset, so a deploy with a missing secret silently shipped an open API. |
| CODE-06 | Security headers set as `<meta http-equiv>` where browsers ignore them | medium | Every page carried `<meta http-equiv="X-Content-Type-Options">` and the docs claimed nosniff was active. It was not. False assurance is worse than a known gap. |
| CODE-07 | CSP present, and free of `unsafe-inline` / `unsafe-eval` / missing `object-src` / missing `base-uri` | medium / low | Without a CSP one injection runs with full privileges. |
| CODE-08 | Deploy publishes a build directory, not the repo root | high | A workflow ran `aws s3 sync ./` to a public bucket behind a handful of `--exclude`s, publishing `.claude/`, internal notes and dev scripts. A deny-list is the wrong shape. |
| CODE-09 | CI hygiene: OIDC subject scoped to a branch, actions pinned to a SHA, minimal token scope, no `github.event` in `run:` | high / medium / low | The trust policy ended in `:*`, so any branch could assume the production deploy role. |
| CODE-10 | `eval`, `new Function`, string timers, `srcdoc`, unchecked `postMessage` | high / medium | Turns data into code, or trusts any frame. |
| CODE-11 | Tokens/passwords/JWTs in `localStorage` / `sessionStorage` | high | Readable by any script on the origin, so one XSS becomes credential theft. |
| CODE-12 | Static file path built from `req.url` without a containment check | high | Path traversal serves arbitrary files. |
| CODE-13 | Lockfile present, no floating versions | medium | Unreproducible builds cannot be audited. |
| CODE-14 | Plaintext `http://` subresources | medium | Blocked as mixed content, or a downgrade. |
| CODE-15 | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `curl -k` | high | Any response can be forged. Legitimate only for a certificate inspector, and then only if the body is untrusted. |
| CODE-16 | `target="_blank"` without `rel="noopener"` | low | Reverse tabnabbing. |

### B. Runtime evaluation — `akretrix-sec url <url>`

| ID | Check | Severity | Why it exists |
| :--- | :--- | :--- | :--- |
| URL-01 | CSP, `X-Content-Type-Options`, `Referrer-Policy`, HSTS, framing protection actually present on the wire | high → low | The only way to know whether a header exists. Distinguishes "served as a header" from "delivered by meta" from "absent". |
| URL-02 | HSTS `max-age` ≥ 6 months with `includeSubDomains` | low | A short max-age leaves a downgrade window. |
| URL-03 | Served CSP free of `unsafe-inline` / `unsafe-eval`, with `object-src`, `base-uri`, `frame-ancestors` | low | `frame-ancestors` **only** works as a header — never from meta. |
| URL-04 | `http://` redirects to HTTPS | high | Otherwise the first request is interceptable. |
| URL-05 | TLS version, cipher, chain validity, certificate expiry window | critical → medium | Catches expiring certs before customers do. |
| URL-06 | Cookies set `Secure`, `HttpOnly`, `SameSite` | high / medium | Session theft and CSRF. |
| URL-07 | `Server` / `X-Powered-By` version banners | low / info | Lets a scanner match a version to a CVE. |
| URL-08 | `.git/config`, `.env`, `.DS_Store`, `package.json`, IaC and internal notes not reachable | critical → info | The live counterpart to CODE-08: verifies what is *actually served*, not what the workflow intended. |
| URL-09 | Directory listing disabled | medium | Enumerable directories reveal unlinked files. |
| URL-10 | `Access-Control-Allow-Origin` neither `*` nor reflected | critical → medium | Sends a foreign `Origin` and checks whether it is echoed. Catches a deploy that shipped without its origin set. |
| URL-11 | No plaintext subresources in the delivered HTML | medium | Mixed content. |
| URL-12 | HTML not cached long | low | Visitors keep running a version whose bug you already fixed. |

---

## Keeping the suite honest

A scanner that quietly stops matching is worse than no scanner, because a clean
report gets read as "we are fine". `test/fixtures/vulnerable/` is a deliberately
insecure fixture containing one instance of each defect class, and the self-test
asserts every check still fires:

```bash
npm run selftest
```

```
  ✓ CODE-01  unescaped remote data in innerHTML
  ✓ CODE-02  escape helper missing quote characters
  ...
PASS: every check still detects its defect.
```

If you change a check, run this. If a check stops firing, fix the check before
trusting any clean report.

The fixture is never deployed and never linked. It exists to be scanned.

Anything under `test/fixtures/` is skipped when scanning a whole project, so a
fixture can never fail a real build. The self-test reaches it by pointing the
scanner directly at the fixture directory.

One caveat: running `akretrix-sec code .` **on this repo** reports findings in
`lib/checks-*.js`, because those files necessarily contain the very patterns they
search for (`eval(`, `rejectUnauthorized: false`, and so on). That is expected.
Point the scanner at frontends, not at itself.

---

## Wiring it into a frontend's CI

Copy `templates/security-tests.yml` into the target frontend's
`.github/workflows/` and adjust `SCAN_PATH` / `SITE_URL`. It lives under
`templates/` rather than this repo's own `.github/` on purpose: as a live
workflow here it would scan the deliberately-vulnerable fixture and fail forever. It runs `code` mode on every PR, and `url` mode
against the deployed site after a release.

Recommended thresholds:

- **PR gate**: `--fail-on high`. Blocks the two classes that have actually bitten
  us — XSS sinks and SSRF — without failing on banner disclosure.
- **Nightly against production**: `--fail-on medium`, so certificate expiry and a
  missing header surface before a customer finds them.

---

## Baseline for a new frontend

Before a new AkreTrix frontend goes public:

1. `akretrix-sec code .` — no `critical` or `high`.
2. Every value reaching `innerHTML` passes through an escaper covering `& < > " '`, or use `textContent`.
3. A CSP is served, with `object-src 'none'` and `base-uri 'none'`.
4. `X-Content-Type-Options`, HSTS and framing protection are **response headers** at the CDN, not meta tags.
5. The deploy publishes one build directory — never the repo root.
6. The OIDC trust policy is pinned to a branch, one role per environment.
7. `akretrix-sec url https://<site>` — no `critical` or `high`.
8. `npm run selftest` passes, so the report above means something.

---

## Known interactions worth remembering

- **A strict CSP breaks `new Function()`.** A JavaScript syntax-checker tool
  validates by compiling with `new Function(src)`, which needs `'unsafe-eval'`.
  Compiling does not execute the body, so it is not an injection sink, but it
  *will* fail under a CSP without `unsafe-eval`. Decide which you want before
  enabling that tool.
- **`rejectUnauthorized: false` is correct in exactly one place** — a tool whose
  job is inspecting a possibly-invalid certificate. CODE-15 flags it at `high`
  with `review` confidence on purpose: it should require a deliberate decision
  every time, not be waved through.
- **SPA catch-all routing hides exposed files.** URL-08 skips a 200 whose body is
  an HTML document for a non-HTML path, because a catch-all rewrite would
  otherwise report every path as exposed. If your host serves real files *and* a
  catch-all, verify by hand as well.
