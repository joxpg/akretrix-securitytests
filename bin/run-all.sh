#!/usr/bin/env bash
#
# run-all.sh — run every security test against every configured target.
#
# One command for the whole estate: static review of each repository, runtime
# review of each deployed site, and a probe of each API endpoint. Targets live in
# targets.conf so this script never needs editing to add one.
#
# Usage:
#   ./bin/run-all.sh                          # all targets in targets.conf
#   ./bin/run-all.sh --only repo              # just the repositories
#   ./bin/run-all.sh --only api               # just the API endpoints
#   ./bin/run-all.sh --config other.conf      # a different target list
#   ./bin/run-all.sh --fail-on critical       # loosen the static gate
#
# Exit codes: 0 everything within threshold · 1 findings at/above it ·
#             2 the harness itself could not run.
#
# Per-target output is written to reports/ so a CI run can attach it.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$HERE/targets.conf"
REPORTS="$HERE/reports"
FAIL_ON="high"
ONLY=""
SKIP_SELFTEST=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)        CONFIG="$2"; shift 2 ;;
    --only)          ONLY="$2"; shift 2 ;;
    --fail-on)       FAIL_ON="$2"; shift 2 ;;
    --skip-selftest) SKIP_SELFTEST=1; shift ;;
    -h|--help)       sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ -f "$CONFIG" ]] || { printf 'Config not found: %s\n' "$CONFIG" >&2; exit 2; }
command -v node >/dev/null || { printf 'node is required\n' >&2; exit 2; }

mkdir -p "$REPORTS"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_bld=$'\033[1m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
[[ -t 1 ]] || { c_red=; c_grn=; c_yel=; c_bld=; c_dim=; c_off=; }

TOTAL=0; PASSED=0; FAILED=0; SKIPPED=0
declare -a SUMMARY=()

record() { SUMMARY+=("$1|$2|$3"); }

banner() {
  printf '\n%s\n' "${c_bld}════════════════════════════════════════════════════════════════${c_off}"
  printf '%s\n'   "${c_bld} $1${c_off}"
  printf '%s\n'   "${c_bld}════════════════════════════════════════════════════════════════${c_off}"
}

# --------------------------------------------------------------------------- #
# The scanner must be proven to still detect its defects before any clean result
# from it is trusted. A silently broken check reports green, which is worse than
# reporting nothing.
# --------------------------------------------------------------------------- #
if (( SKIP_SELFTEST == 0 )); then
  banner "Scanner integrity"
  if node "$HERE/test/selftest.js" > "$REPORTS/selftest-$STAMP.txt" 2>&1; then
    printf '  %sPASS%s  every check still detects its defect\n' "$c_grn" "$c_off"
  else
    printf '  %sFAIL%s  the scanner no longer detects one or more defects\n' "$c_red" "$c_off"
    printf '        %s\n' "$REPORTS/selftest-$STAMP.txt"
    printf '\n  Refusing to continue: results from a broken scanner are not evidence.\n'
    printf '  Re-run with --skip-selftest to override.\n\n'
    exit 2
  fi
fi

# --------------------------------------------------------------------------- #
run_repo() {
  local path="$1" name
  name="$(basename "$path")"
  TOTAL=$((TOTAL+1))
  printf '\n%s── repo: %s%s\n' "$c_dim" "$name" "$c_off"
  if [[ ! -d "$path" ]]; then
    printf '  %sSKIP%s  not found at %s\n' "$c_yel" "$c_off" "$path"
    SKIPPED=$((SKIPPED+1)); record "repo" "$name" "skipped (not found)"
    return
  fi
  local json="$REPORTS/code-$name-$STAMP.json"

  # Scanned ONCE. An earlier version ran the scanner twice per repo — once for a
  # text report and again for JSON — which doubled the wall clock on the larger
  # repositories for no extra information. JSON carries everything, so the
  # human-readable summary and the severity gate are both derived from it.
  node "$HERE/bin/akretrix-sec.js" code "$path" --json --fail-on never > "$json" 2>"$json.err"
  local rc=$?
  if (( rc != 0 )) || [[ ! -s "$json" ]]; then
    printf '  %sFAIL%s  scanner error (exit %s)\n' "$c_red" "$c_off" "$rc"
    [[ -s "$json.err" ]] && tail -3 "$json.err" | sed 's/^/        /'
    FAILED=$((FAILED+1)); record "repo" "$name" "FAIL — scanner error"
    return
  fi
  rm -f "$json.err"

  # One node invocation returns: counts line, gate verdict, and the top findings.
  local parsed
  parsed="$(FAIL_ON="$FAIL_ON" node -e '
    const order = ["critical","high","medium","low","info"];
    const d = require(process.argv[1]);
    const c = d.counts || {};
    const limit = order.indexOf(process.env.FAIL_ON);
    const breached = (d.findings || []).some(f => order.indexOf(f.severity) <= limit && limit >= 0);
    const counts = order.filter(k => c[k]).map(k => c[k] + " " + k).join(", ") || "no findings";
    const top = (d.findings || [])
      .filter(f => order.indexOf(f.severity) <= Math.max(limit, 1))
      .slice(0, 6)
      .map(f => `${f.severity.toUpperCase()} ${f.id} ${f.where || ""} — ${f.title}`);
    process.stdout.write([breached ? "BREACH" : "OK", counts, ...top].join("\n"));
  ' "$json" 2>/dev/null)"

  local verdict counts
  verdict="$(head -1 <<<"$parsed")"
  counts="$(sed -n '2p' <<<"$parsed")"

  if [[ "$verdict" == "OK" ]]; then
    printf '  %sPASS%s  %s\n' "$c_grn" "$c_off" "$counts"
    PASSED=$((PASSED+1)); record "repo" "$name" "pass — $counts"
  else
    printf '  %sFAIL%s  %s (at or above %s)\n' "$c_red" "$c_off" "$counts" "$FAIL_ON"
    tail -n +3 <<<"$parsed" | sed 's/^/        /'
    FAILED=$((FAILED+1)); record "repo" "$name" "FAIL — $counts"
  fi
  printf '        %s\n' "$json"
}

run_site() {
  local url="$1"
  TOTAL=$((TOTAL+1))
  printf '\n%s── site: %s%s\n' "$c_dim" "$url" "$c_off"
  local txt="$REPORTS/url-$(printf '%s' "$url" | tr -c 'a-zA-Z0-9' '-')-$STAMP.txt"
  node "$HERE/bin/akretrix-sec.js" url "$url" --fail-on "$FAIL_ON" > "$txt" 2>&1
  local rc=$?
  local summary
  summary="$(grep -E '^Summary:' "$txt" | sed 's/^Summary: //' || true)"
  if (( rc == 0 )); then
    printf '  %sPASS%s  %s\n' "$c_grn" "$c_off" "${summary:-no findings}"
    PASSED=$((PASSED+1)); record "site" "$url" "pass — ${summary:-none}"
  else
    printf '  %sFAIL%s  %s\n' "$c_red" "$c_off" "${summary:-see report}"
    grep -E '^(CRITICAL|HIGH)' "$txt" | head -6 | sed 's/^/        /'
    FAILED=$((FAILED+1)); record "site" "$url" "FAIL — ${summary:-see report}"
  fi
  printf '        %s\n' "$txt"
}

run_api() {
  local url="$1" origin="${2:-}"
  TOTAL=$((TOTAL+1))
  printf '\n%s── api:  %s%s\n' "$c_dim" "$url" "$c_off"
  local txt="$REPORTS/api-$(printf '%s' "$url" | tr -c 'a-zA-Z0-9' '-')-$STAMP.txt"
  bash "$HERE/bin/api-probe.sh" "$url" "$origin" > "$txt" 2>&1
  local rc=$?
  local tally
  tally="$(grep -E '^[0-9]+ failure|failures' "$txt" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' || true)"
  if (( rc == 0 )); then
    printf '  %sPASS%s  %s\n' "$c_grn" "$c_off" "${tally:-0 failures}"
    PASSED=$((PASSED+1)); record "api" "$url" "pass — ${tally:-0 failures}"
  else
    printf '  %sFAIL%s  %s\n' "$c_red" "$c_off" "${tally:-see report}"
    grep -E '  FAIL ' "$txt" | head -6 | sed 's/^/      /'
    FAILED=$((FAILED+1)); record "api" "$url" "FAIL — ${tally:-see report}"
  fi
  printf '        %s\n' "$txt"
}

# --------------------------------------------------------------------------- #
banner "Targets from $(basename "$CONFIG")"
CONFIG_DIR="$(cd "$(dirname "$CONFIG")" && pwd)"

while read -r kind arg1 arg2 _rest; do
  [[ -z "${kind:-}" || "$kind" == \#* ]] && continue
  [[ -n "$ONLY" && "$kind" != "$ONLY" ]] && continue
  case "$kind" in
    repo)
      # Resolve relative to the config file so the script works from anywhere.
      if [[ "$arg1" == /* ]]; then run_repo "$arg1"; else run_repo "$CONFIG_DIR/$arg1"; fi ;;
    site) run_site "$arg1" ;;
    api)  run_api "$arg1" "${arg2:-}" ;;
    *)    printf '\n  %sSKIP%s  unknown target type "%s"\n' "$c_yel" "$c_off" "$kind" ;;
  esac
done < "$CONFIG"

# --------------------------------------------------------------------------- #
banner "Summary"
printf '\n'
for row in "${SUMMARY[@]}"; do
  IFS='|' read -r kind name result <<<"$row"
  case "$result" in
    FAIL*)    marker="${c_red}✗${c_off}" ;;
    skipped*) marker="${c_yel}−${c_off}" ;;
    *)        marker="${c_grn}✓${c_off}" ;;
  esac
  printf '  %s %-6s %-42s %s\n' "$marker" "$kind" "$(printf '%.42s' "$name")" "$result"
done

printf '\n  %d target(s): %s%d passed%s, %s%d failed%s, %d skipped\n' \
  "$TOTAL" "$c_grn" "$PASSED" "$c_off" "$c_red" "$FAILED" "$c_off" "$SKIPPED"
printf '  static gate: --fail-on %s · reports in %s\n\n' "$FAIL_ON" "${REPORTS/#$HOME/~}"

(( FAILED > 0 )) && exit 1
exit 0
