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
#   ./bin/api-probe.sh <base-url> [expected-origin]
#
# Examples:
#   ./bin/api-probe.sh https://abc123.lambda-url.us-east-1.on.aws/ https://akretrix.com
#
# Run only against endpoints your organisation controls.

set -uo pipefail

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
head1 "7. Rate limiting"
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
