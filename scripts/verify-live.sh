#!/usr/bin/env bash
# myav live verification — read-only, safe to run at any time.
#
# It answers one question: "is the protection actually working on THIS machine?"
# It does not install anything, does not change settings and does not delete files.
# Every check prints PASS / WARN / FAIL and the script exits non-zero only on FAIL.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

BIN="./bin/myav"
if [ ! -x "$BIN" ]; then
  BIN="myav"
fi

pass=0
warn=0
fail=0

section() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf 'PASS  %s\n' "$*"; pass=$((pass + 1)); }
meh()  { printf 'WARN  %s\n' "$*"; warn=$((warn + 1)); }
bad()  { printf 'FAIL  %s\n' "$*"; fail=$((fail + 1)); }

section "myav version and platform"
if "$BIN" version; then ok "CLI starts"; else bad "CLI does not start"; fi

section "Dependencies (myav doctor)"
if "$BIN" doctor; then
  ok "doctor reports no hard failure"
else
  bad "doctor found a problem — read the FAIL lines above"
fi

section "YARA rules"
if "$BIN" rules status 2>/dev/null | grep -q "rule files: *[1-9]"; then
  ok "rule pack present"
else
  meh "no YARA rules yet — run: $BIN rules fetch --accept-license"
fi

section "Scheduled jobs"
if "$BIN" schedules status 2>/dev/null | grep -q "installed:"; then
  ok "at least one scheduled job is installed"
else
  meh "no scheduled job yet — run: $BIN schedules install --yes"
fi

section "Quarantine"
if "$BIN" quarantine list >/dev/null 2>&1; then
  ok "quarantine database is readable"
else
  bad "quarantine database is not readable"
fi

section "EICAR end-to-end self-test"
"$BIN" selftest
code=$?
case "$code" in
  0) ok "EICAR detected, quarantined, restored byte-for-byte" ;;
  5) meh "EICAR test INCONCLUSIVE (usually Windows Defender removed the file first) — see the message above" ;;
  *) bad "EICAR self-test failed — the detection chain is broken" ;;
esac

printf '\n----------------------------------------\n'
printf 'PASS: %d   WARN: %d   FAIL: %d\n' "$pass" "$warn" "$fail"
if [ "$fail" -gt 0 ]; then
  printf 'Verdict: NOT HEALTHY — fix the FAIL lines before trusting the scanner.\n'
  exit 1
fi
if [ "$warn" -gt 0 ]; then
  printf 'Verdict: WORKING, with warnings. Warnings are optional steps or environment limits.\n'
  exit 0
fi
printf 'Verdict: HEALTHY.\n'
