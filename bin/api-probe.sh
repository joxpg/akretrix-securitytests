#!/usr/bin/env bash
#
# api-probe.sh — security probe for an HTTP API endpoint.
#
# Companion to `akretrix-sec url`, which is built for HTML pages: on a JSON API
# its CSP / framing / mixed-content checks are meaningless and only add noise.
# This covers what actually matters for an endpoint: who may call it, whether it
# can be turned into a proxy, and what it discloses when it fails.
#
# READ-ONLY BY DEFAULT. It never sends POST/PUT/PATCH/DELETE bodies, because an
# API that accepts them usually has a side effect — a contact endpoint sends a
# real email. Method handling is probed without a payload.
#
# Usage:
#   ./bin/api-probe.sh <base-url> [expected-origin] [--verify-captcha-gate]
#
# --verify-captcha-gate sends ONE POST with no anti-bot token, to prove the
# endpoint rejects it. This is the only probe that sends a body, which is why it
# is opt-in: on an endpoint whose captcha check runs AFTER its side effects, that
# POST would still send the email or write the record. Confirm the ordering before
# using it.
#
# Examples:
#   ./bin/api-probe.sh https://abc123.lambda-url.us-east-1.on.aws/ https://akretrix.com
#
# Run only against endpoints your organisation controls.

set -uo pipefail

VERIFY_CAPTCHA_GATE=0
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-captcha-gate) VERIFY_CAPTCHA_GATE=1; shift ;;
    -h|--help) sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
set -- "${POSITIONAL[@]:-}"

API="${1:-}"
EXPECTED_ORIGIN="${2:-}"
FOREIGN_ORIGIN="https://not-your-origin.example"
TIMEOUT=20
FAILURES=0
WARNINGS=0

if [[ -z "$API" ]]; then
  sed -n '3,24p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
# The URL is used EXACTLY as given. Do not normalise a trailing slash onto it:
# on a path-routed API (api.example.com/free-tools) adding one changes the route
# and returns 404, so every check would then be probing a non-existent endpoint
# and reporting passes that mean nothing.
HOST="$(printf '%s' "$API" | sed -E 's#^https?://([^/:]+).*#\1#')"

# Appends a query string, respecting a base URL that already has one.
with_query() {
  case "$API" in
    *\?*) printf '%s&%s' "$API" "$1" ;;
    *)    printf '%s?%s' "$API" "$1" ;;
  esac
}

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
[[ -t 1 ]] || { c_red=; c_grn=; c_yel=; c_dim=; c_off=; }

pass() { printf "  ${c_grn}PASS${c_off}  %s\n" "$1"; }
fail() { printf "  ${c_red}FAIL${c_off}  %s\n" "$1"; FAILURES=$((FAILURES+1)); }
warn() { printf "  ${c_yel}WARN${c_off}  %s\n" "$1"; WARNINGS=$((WARNINGS+1)); }
info() { printf "  ${c_dim}····${c_off}  %s\n" "$1"; }
head1() { printf "\n${c_dim}%s${c_off}\n" "$1"; }

hdr()  { curl -sS -o /dev/null -D - --max-time "$TIMEOUT" "$@" 2>/dev/null; }
body() { curl -sS --max-time "$TIMEOUT" "$@" 2>/dev/null; }
code() { curl -sS -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" "$@" 2>/dev/null; }

printf "\nAPI security probe — %s\n" "$API"

# --------------------------------------------------------------------------- #
head1 "1. Transport"
if [[ "$API" == https://* ]]; then
  pass "endpoint is HTTPS"
  # Captured to a variable rather than piped into `grep -q`. Under `set -o
  # pipefail`, grep -q exits on first match and SIGPIPEs openssl, so the pipeline
  # returns non-zero even when the pattern matched — which reported a refused
  # TLS 1.0 handshake as "accepted".
  TLS10_OUT="$(echo | openssl s_client -connect "$HOST:443" -servername "$HOST" -tls1 2>&1 || true)"
  if grep -qiE "alert (number )?70|alert protocol version|no protocol|unsupported protocol|handshake fail|Cipher is \(NONE\)" <<<"$TLS10_OUT"; then
    pass "TLS 1.0 refused"
  elif grep -qE "Cipher is [A-Z0-9]" <<<"$TLS10_OUT"; then
    fail "TLS 1.0 accepted — deprecated and fails most compliance baselines"
  else
    warn "TLS 1.0 result inconclusive (local openssl may not offer TLS 1.0)"
  fi
  NOT_AFTER="$(echo | openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
  if [[ -n "$NOT_AFTER" ]]; then
    END_EPOCH="$(date -j -f "%b %d %T %Y %Z" "$NOT_AFTER" +%s 2>/dev/null || date -d "$NOT_AFTER" +%s 2>/dev/null)"
    if [[ -n "${END_EPOCH:-}" ]]; then
      DAYS=$(( (END_EPOCH - $(date +%s)) / 86400 ))
      if   (( DAYS < 0  )); then fail "certificate EXPIRED ($NOT_AFTER)"
      elif (( DAYS < 21 )); then warn "certificate expires in $DAYS day(s)"
      else pass "certificate valid for $DAYS more day(s)"; fi
    fi
  fi
else
  fail "endpoint is plaintext HTTP — traffic is readable and modifiable in transit"
fi

# --------------------------------------------------------------------------- #
head1 "2. Authentication / exposure"
ROOT_CODE="$(code "$API")"
info "unauthenticated GET -> HTTP $ROOT_CODE"
if [[ "$ROOT_CODE" == "404" ]]; then
  fail "endpoint returned 404 — the URL is probably wrong (a path-routed API is sensitive to a trailing slash). Every check below would be probing nothing; fix the URL and re-run."
fi
case "$ROOT_CODE" in
  401|403) pass "endpoint requires authentication" ;;
  405)     info "method not allowed at root (the API likely only accepts POST)" ;;
  *)       warn "endpoint answers unauthenticated requests (HTTP $ROOT_CODE). Acceptable for a public API, but it must then be rate limited and free of side effects." ;;
esac

# --------------------------------------------------------------------------- #
head1 "3. CORS"
ACAO_FOREIGN="$(hdr -H "Origin: $FOREIGN_ORIGIN" "$API" | tr -d '\r' \
  | grep -i '^access-control-allow-origin:' | head -1 | cut -d' ' -f2-)"
ACAC="$(hdr -H "Origin: $FOREIGN_ORIGIN" "$API" | tr -d '\r' \
  | grep -i '^access-control-allow-credentials:' | head -1 | cut -d' ' -f2-)"

if [[ -z "$ACAO_FOREIGN" ]]; then
  pass "no Access-Control-Allow-Origin returned for a foreign Origin"
elif [[ "$ACAO_FOREIGN" == "*" ]]; then
  if [[ "${ACAC,,}" == "true" ]]; then
    fail "ACAO is '*' AND Allow-Credentials is true — any site can read authenticated responses"
  else
    fail "ACAO is '*' — any website can read this API from a visitor's browser"
  fi
elif [[ "$ACAO_FOREIGN" == "$FOREIGN_ORIGIN" ]]; then
  fail "ACAO reflects any supplied Origin ($FOREIGN_ORIGIN echoed back) — equivalent to '*', but also works with credentials"
else
  pass "ACAO pinned to a single origin: $ACAO_FOREIGN"
  if [[ -n "$EXPECTED_ORIGIN" && "$ACAO_FOREIGN" != "$EXPECTED_ORIGIN" ]]; then
    warn "expected $EXPECTED_ORIGIN but got $ACAO_FOREIGN"
  fi
fi

# --------------------------------------------------------------------------- #
head1 "4. SSRF containment (skipped unless the API takes a host/url parameter)"
# Only meaningful for an API that dials a caller-supplied target. Each of these
# must be refused; a connection result means the endpoint is a usable proxy and
# port scanner. Detection is by response content, so an API without these
# parameters simply reports "not applicable".
SSRF_APPLICABLE=0
declare -a SSRF_CASES=(
  "tool=port-check&host=127.0.0.1&port=22|loopback port scan"
  "tool=port-check&host=localhost&port=22|loopback via hostname (DNS path)"
  "tool=port-check&host=10.0.0.1&port=80|RFC1918 private range"
  "tool=http-headers&url=http://169.254.169.254/latest/meta-data/|cloud instance metadata"
  "tool=curl&url=http://127.0.0.1:9001/2018-06-01/runtime/invocation/next|Lambda runtime API"
  "tool=http-headers&url=http://[::1]/|IPv6 loopback"
  "tool=http-headers&url=file:///etc/passwd|file:// scheme"
  "tool=curl&url=gopher://127.0.0.1:70/|gopher:// scheme"
)
for entry in "${SSRF_CASES[@]}"; do
  qs="${entry%%|*}"; label="${entry##*|}"
  resp="$(body "$(with_query "$qs")")"
  [[ -z "$resp" ]] && continue
  # Routing/method errors mean the probe never reached any dialling code, so this
  # is "not applicable", NOT a refusal. Counting them as refusals reported a
  # containment guard on an endpoint that only accepts POST — a false pass, which
  # is worse than a miss because it reads as proof of a control that isn't there.
  if grep -qiE 'unknown or missing|missing "tool"|method not allowed|not found|forbidden' <<<"$resp"; then continue; fi
  SSRF_APPLICABLE=1
  if grep -qiE 'refusing to connect|non-public|only http' <<<"$resp"; then
    pass "refused: $label"
  elif grep -qiE '"open":true|"status":[0-9]|"reachable":true|connectTimeMs' <<<"$resp"; then
    fail "CONNECTED to $label — this endpoint is a usable proxy/port scanner"
  else
    warn "$label -> unclear: $(head -c 90 <<<"$resp")"
  fi
done
if (( SSRF_APPLICABLE == 0 )); then
  info "not applicable — no host/url parameter recognised on this endpoint"
else
  legit="$(body "$(with_query "tool=port-check&host=example.com&port=443")")"
  grep -qE '"open":(true|false)' <<<"$legit" \
    && pass "legitimate public target still works (guard is not over-blocking)" \
    || warn "legitimate public target did not return a normal result: $(head -c 90 <<<"$legit")"
fi

# --------------------------------------------------------------------------- #
head1 "5. Method handling (no bodies sent — a POST here could have side effects)"
for m in GET OPTIONS HEAD PUT DELETE PATCH TRACE; do
  mc="$(code -X "$m" "$API")"
  case "$m:$mc" in
    TRACE:200) fail "TRACE is enabled (HTTP 200) — can echo headers back" ;;
    *:200|*:204) info "$m -> $mc" ;;
    *) info "$m -> $mc" ;;
  esac
done

# --------------------------------------------------------------------------- #
head1 "6. Error verbosity and information disclosure"
ERRBODY="$(body "$(with_query "tool=__probe__&host=&port=")")"
if grep -qiE 'at [A-Za-z]+ \(|/var/task/|node_modules|Traceback|\.js:[0-9]+|stack' <<<"$ERRBODY"; then
  fail "error response leaks a stack trace or internal path"
else
  pass "error response does not leak stack traces or internal paths"
fi
BANNERS="$(hdr "$API" | tr -d '\r' | grep -iE '^(server|x-powered-by|x-aspnet-version):' || true)"
if [[ -n "$BANNERS" ]]; then
  grep -qE '[0-9]+\.[0-9]+' <<<"$BANNERS" \
    && warn "version banner disclosed: $(tr '\n' ' ' <<<"$BANNERS")" \
    || info "stack banner: $(tr '\n' ' ' <<<"$BANNERS")"
else
  pass "no Server / X-Powered-By banner"
fi

# --------------------------------------------------------------------------- #
head1 "7. Credential exposure in responses"
# An API can leak a secret in ways the source scan cannot see: an error handler
# that serialises its config, a debug branch left enabled, a header added by a
# proxy. These probes read only what the endpoint volunteers.
CRED_PATTERN='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|xox[baprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{35}|(postgres|mysql|mongodb)(\+srv)?://[^[:space:]:@/]+:[^[:space:]:@/]+@'
# Anything a caller could send that might get echoed back into an error.
CRED_PROBES=("" "?tool=__probe__" "?debug=1" "?verbose=true" "?tool=curl&url=" "?config=1")
CRED_HITS=0
for probe in "${CRED_PROBES[@]}"; do
  if [[ -z "$probe" ]]; then resp="$(body "$API"; hdr "$API")"; else resp="$(body "$(with_query "${probe#\?}")")"; fi
  # Placeholders and vendor test values are not leaks.
  filtered="$(grep -oE "$CRED_PATTERN" <<<"$resp" 2>/dev/null | grep -viE 'EXAMPLE|YOUR[_-]|PLACEHOLDER|DUMMY|REDACTED|SAMPLE' || true)"
  if [[ -n "$filtered" ]]; then
    CRED_HITS=$((CRED_HITS+1))
    # Redacted: this output gets attached to CI runs.
    fail "response leaks a credential-shaped value for '${probe:-/}': $(head -c 12 <<<"$filtered")… (rotate it, then remove it from the response)"
  fi
done

# Env/config keys echoed into a body are the usual precursor to a real leak.
ENV_ECHO="$(body "$(with_query 'tool=__probe__')" | grep -oiE '"(env|environment|config|secret|process)"[[:space:]]*:' || true)"
if [[ -n "$ENV_ECHO" ]]; then
  fail "response serialises configuration state ($ENV_ECHO) — one refactor away from including a secret"
  CRED_HITS=$((CRED_HITS+1))
fi

# Headers a proxy or framework sometimes adds.
LEAKY_HDRS="$(hdr "$API" | tr -d '\r' | grep -iE '^(x-amz-security-token|authorization|x-api-key|set-cookie):' || true)"
if [[ -n "$LEAKY_HDRS" ]]; then
  fail "response returns a credential-bearing header: $(cut -d: -f1 <<<"$LEAKY_HDRS" | tr '\n' ' ')"
  CRED_HITS=$((CRED_HITS+1))
fi

if (( CRED_HITS == 0 )); then
  pass "no credentials, config dumps or credential-bearing headers in ${#CRED_PROBES[@]} probed responses"
fi

# --------------------------------------------------------------------------- #
head1 "8. Anti-bot gate (opt-in: --verify-captcha-gate)"
# Fail-closed behaviour is invisible from the source: the secret could be unset in
# this environment, the IAM grant to read it could be missing, or a CloudFormation
# dynamic reference could have shipped unresolved. All three produce a working
# deploy and a defenceless form. Only a live request distinguishes them.
if (( VERIFY_CAPTCHA_GATE == 1 )); then
  GATE_BODY='{"fullName":"akretrix-securitytests probe","workEmail":"probe@example.invalid","service":"security-probe","message":"Automated anti-bot gate check. No token supplied; this must be rejected.","submitDurationMs":9000}'
  GATE_RESP="$(curl -sS -o - -w '\n<<HTTP:%{http_code}>>' --max-time "$TIMEOUT" \
    -X POST "$API" \
    -H 'Content-Type: application/json' \
    ${EXPECTED_ORIGIN:+-H "Origin: $EXPECTED_ORIGIN"} \
    -d "$GATE_BODY" 2>/dev/null || true)"
  GATE_CODE="$(grep -oE '<<HTTP:[0-9]+>>' <<<"$GATE_RESP" | grep -oE '[0-9]+' || echo 0)"
  GATE_JSON="$(sed 's/<<HTTP:[0-9]*>>//' <<<"$GATE_RESP")"

  if grep -qiE '"(success|ok)"[[:space:]]*:[[:space:]]*true' <<<"$GATE_JSON"; then
    fail "endpoint ACCEPTED a submission with no anti-bot token (HTTP $GATE_CODE) — the gate is not enforced, or it fails OPEN"
  elif [[ "$GATE_CODE" == "403" ]]; then
    warn "rejected at the Origin check (HTTP 403) before reaching the anti-bot gate — pass the expected origin as the 2nd argument to test the gate itself"
  elif [[ "$GATE_CODE" =~ ^(400|401|422)$ ]]; then
    CODE_FIELD="$(grep -oE '"code"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$GATE_JSON" | cut -d'"' -f4 || true)"
    # A 4xx alone proves nothing. An endpoint that rejects the request for an
    # unrelated reason — a missing query parameter, a schema mismatch — looks
    # identical, and calling that a pass reports an anti-bot control the endpoint
    # does not have. Require the response to actually mention one.
    if grep -qiE 'captcha|turnstile|recaptcha|hcaptcha|verification failed|challenge' <<<"$GATE_JSON"; then
      pass "tokenless submission rejected by the anti-bot gate (HTTP $GATE_CODE${CODE_FIELD:+, code=$CODE_FIELD})"
      # A misconfigured secret and a bad token are different problems; the
      # endpoint should say which, so an operator is not left guessing.
      [[ -z "$CODE_FIELD" ]] && warn "rejection carried no machine-readable code — the frontend cannot tell an expired challenge from a genuine failure"
    else
      info "rejected with HTTP $GATE_CODE, but for an unrelated reason ($(head -c 70 <<<"$GATE_JSON" | tr -d '\n')) — no anti-bot gate detected on this endpoint"
    fi
  elif [[ "$GATE_CODE" == "500" ]]; then
    CODE_FIELD="$(grep -oE '"code"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$GATE_JSON" | cut -d'"' -f4 || true)"
    if [[ "$CODE_FIELD" == *misconfigured* ]]; then
      fail "the anti-bot secret is NOT configured in this environment (code=$CODE_FIELD) — it fails closed, so the form currently rejects every genuine submission too"
    else
      fail "tokenless submission caused a server error (HTTP 500) instead of a clean rejection"
    fi
  elif [[ "$GATE_CODE" == "503" ]]; then
    warn "verifier unreachable from the server (HTTP 503) — fails closed, but the form is rejecting real users right now"
  elif [[ "$GATE_CODE" == "405" ]]; then
    info "endpoint does not accept POST — no anti-bot gate to test here"
  else
    warn "unexpected response to a tokenless submission: HTTP $GATE_CODE $(head -c 90 <<<"$GATE_JSON")"
  fi
else
  info "not run — pass --verify-captcha-gate to send one tokenless POST and prove the gate rejects it"
  info "only do so when the captcha check runs BEFORE any email/database side effect"
fi

# --------------------------------------------------------------------------- #
head1 "9. Rate limiting"
# Intentionally NOT load tested: flooding your own endpoint costs money and is a
# self-inflicted DoS. Verify the cap in configuration instead.
info "not probed by design — flooding the endpoint would cost money and be a self-DoS"
info "check instead: Lambda ReservedConcurrentExecutions, or WAF / API Gateway throttling"

# --------------------------------------------------------------------------- #
printf "\n%s\n" "-------------------------------------------------------------"
if (( FAILURES > 0 )); then
  printf "${c_red}%d failure(s)${c_off}, %d warning(s)\n\n" "$FAILURES" "$WARNINGS"
  exit 1
fi
printf "${c_grn}0 failures${c_off}, %d warning(s)\n\n" "$WARNINGS"
exit 0
