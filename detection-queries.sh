#!/usr/bin/env bash
#===============================================================================
# detection-queries.sh — php2shell-lab detection queries (run with sudo).
#
# Plain mode: prints every query a defender would run on this box, with output.
# --check TOKEN : runs the same queries in assertion mode and exits 0 only if
#                 ALL of them fired for the given canary token.
#===============================================================================
set -u

LAB_DIR="/var/lib/php2shell-lab"
WEBROOT="/var/www/lab"
NGX_LOG="/var/log/nginx/lab-access.log"
SESS_DIR="/var/lib/php/sessions"

CHECK=0
if [ "${1:-}" = "--check" ]; then
  CHECK=1
  TOKEN="${2:-$(cat "$LAB_DIR/last-token" 2>/dev/null || echo php2shell-lab)}"
else
  TOKEN="${1:-$(cat "$LAB_DIR/last-token" 2>/dev/null || echo php2shell-lab)}"
fi
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo bash /vagrant/detection-queries.sh"; exit 1; }

fail=0
chk() { # $1=label  $2=rc(0=expected-hit)
  if [ "$2" -eq 0 ]; then
    printf '[PASS] %s\n' "$1"
  else
    printf '[FAIL] %s\n' "$1"
    fail=1
  fi
}

printf 'canary token: %s\n\n' "$TOKEN"

#--------------------------------- raw queries --------------------------------
show() { printf '\n--- %s ---\n' "$1"; }

show "auditd: webroot writes (key lab_webroot)"
ausearch -k lab_webroot -ts today 2>/dev/null | tail -n 25 || true
show "auditd: www-data execve (key lab_www_exec)"
ausearch -k lab_www_exec -ts today 2>/dev/null | tail -n 25 || true
show "auditd: session dir writes (key lab_sessions)"
ausearch -k lab_sessions -ts today 2>/dev/null | tail -n 15 || true
show "nginx: access-log canary"
grep -F "$TOKEN" "$NGX_LOG" 2>/dev/null | tail -n 5 || true
show "php: session-file canary"
grep -rlF "$TOKEN" "$SESS_DIR" 2>/dev/null | head -n 5 || true
show "webroot canary file"
ls -l "${WEBROOT}/canary-${TOKEN}.php" 2>/dev/null || true

[ "$CHECK" -eq 1 ] || exit 0

#--------------------------------- assertions ---------------------------------
printf '\n-- detection assertions --\n'
ausearch -k lab_webroot -ts today 2>/dev/null | grep -q "canary-${TOKEN}" \
  && chk "auditd lab_webroot fired for canary file" 0 || chk "auditd lab_webroot fired for canary file" 1
ausearch -k lab_www_exec -ts today 2>/dev/null | grep -qE 'execve|/bin/sh|curl' \
  && chk "auditd lab_www_exec fired for www-data execve" 0 || chk "auditd lab_www_exec fired for www-data execve" 1
ausearch -k lab_sessions -ts today 2>/dev/null | grep -q "$SESS_DIR" \
  && chk "auditd lab_sessions fired for session writes" 0 || chk "auditd lab_sessions fired for session writes" 1
grep -qF "$TOKEN" "$NGX_LOG" 2>/dev/null \
  && chk "nginx access log contains canary" 0 || chk "nginx access log contains canary" 1
grep -rlqF "$TOKEN" "$SESS_DIR" 2>/dev/null \
  && chk "session file contains canary (upload_progress record)" 0 || chk "session file contains canary (upload_progress record)" 1
[ -f "${WEBROOT}/canary-${TOKEN}.php" ] \
  && chk "webroot canary file present" 0 || chk "webroot canary file present" 1

printf '\n'
[ "$fail" -eq 0 ] && { echo "ALL DETECTIONS FIRED"; exit 0; }
echo "SOME DETECTIONS MISSED - see raw query output above"
exit 1
