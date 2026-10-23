#!/usr/bin/env bash
#===============================================================================
# validate.sh — php2shell-lab phase validation (run INSIDE the VM with sudo).
#
# Usage: sudo bash /vagrant/validate.sh <phase>
#   baseline            scanner verdict matches the recorded provision truth
#                       (vulnerable -> rc 1 + [VULN], fixed -> rc 0)
#   ttps                all detection queries fired on the last canary token
#   upgraded-unrestarted checker catches the restart gap via /proc  (rc 1)
#   fixed               after restart: exit 0 + running version >= fix level
#===============================================================================
set -u

LAB_DIR="/var/lib/php2shell-lab"
CHECKER="/vagrant/php2shell-check.sh"
LAB_PHP="${LAB_PHP:-8.2}"
case "$LAB_PHP" in
  8.2) FIXED="8.2.35" ;; 8.3) FIXED="8.3.36" ;;
  8.4) FIXED="8.4.27" ;; 8.5) FIXED="8.5.12" ;;
  *)   FIXED="8.2.35" ;;
esac

phase="${1:-}"
[ -n "$phase" ] || { printf 'usage: %s <baseline|ttps|upgraded-unrestarted|fixed>\n' "$0"; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -f "$CHECKER" ] || { echo "checker not found at $CHECKER (synced folder broken?)"; exit 1; }

PASS=0; FAIL=0
ok()   { printf '[PASS] %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '[FAIL] %s\n' "$*"; FAIL=1; }
ver_ge() { [ "$1" = "$2" ] || [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]; }

out=""; rc=0
run_checker() {
  out="$(bash "$CHECKER" --once --no-color --log /tmp/lab-checker.log 2>&1)"; rc=$?
}

case "$phase" in

  baseline)
    run_checker
    base="$(cat "$LAB_DIR/baseline" 2>/dev/null || echo vulnerable)"
    ver="$(cat "$LAB_DIR/installed-version" 2>/dev/null || echo '?')"
    printf 'provision recorded: baseline=%s php=%s | checker rc=%s\n' "$base" "$ver" "$rc"
    if [ "$base" = "vulnerable" ]; then
      [ "$rc" -eq 1 ] && ok "checker exit 1 for pre-fix build ${ver}" \
                      || bad "expected exit 1, got ${rc} (already patched? re-provision)"
      printf '%s' "$out" | grep -q '\[VULN\]' && ok "output contains [VULN] verdict" \
                                             || bad "no [VULN] verdict in output"
    else
      [ "$rc" -eq 0 ] && ok "checker exit 0 for fixed build ${ver}" \
                      || bad "expected exit 0, got ${rc}"
    fi
    ;;

  ttps)
    token="$(cat "$LAB_DIR/last-token" 2>/dev/null || true)"
    [ -n "$token" ] || { bad "no canary token - run simulate-ttps.sh first"; exit 1; }
    bash /vagrant/detection-queries.sh --check "$token"
    ;;

  upgraded-unrestarted)
    if [ -e "$LAB_DIR/drill-noop" ]; then
      printf '[SKIP] baseline was already fixed - no restart gap possible\n'
      exit 0
    fi
    run_checker
    [ "$rc" -eq 1 ] && ok "checker exit 1 while workers still run the old binary" \
                    || bad "expected exit 1 (restart gap NOT caught) - got ${rc}"
    printf '%s' "$out" | grep -Eqi '\(deleted\)|replaced binary|still executes|pre-patch' \
      && ok "output identifies the deleted/old binary via /proc" \
      || bad "no /proc restart-gap finding in output"
    printf '%s' "$out" | grep -q '\[VULN\]' \
      && ok "restart gap surfaced as [VULN]" || bad "no [VULN] verdict for the gap"
    ;;

  fixed)
    run_checker
    ver="$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo none)"
    printf 'running php: %s (fix level %s)\n' "$ver" "$FIXED"
    ver_ge "$ver" "$FIXED" && ok "installed PHP >= ${FIXED}" \
                           || bad "php ${ver} is below fix level ${FIXED}"
    [ "$rc" -eq 0 ] && ok "checker exit 0 - ALL CLEAR" \
                    || bad "expected exit 0, got ${rc} (restart fpm? residual unknowns?)"
    ;;

  *) printf 'unknown phase: %s\n' "$phase"; exit 64 ;;
esac

printf '\n== phase "%s": %d passed, %s ==\n' "$phase" "$PASS" \
  "$([ "$FAIL" -eq 0 ] && echo "no failures" || echo "FAILURES PRESENT")"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
