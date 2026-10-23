#!/usr/bin/env bash
#===============================================================================
# php2shell-check.sh — exposure checker for "php2shell"
#                      CVE-2026-109618 / CVE-2026-109619 (PHP core RCEs)
#
# Two critical RCEs in PHP core (CVSS v4.0 9.2), fixed by the PHP security
# release of 2026-10-21 14:00 UTC. An upgraded but NOT-restarted PHP runtime
# is still vulnerable: the patch only becomes active once processes reload
# the new binary. No configuration change replaces upgrading.
#
# First fixed upstream versions:
#     8.2 -> 8.2.35      8.3 -> 8.3.36      8.4 -> 8.4.27      8.5 -> 8.5.12
#     8.1 and older are end-of-life: no fix will ever exist -> always VULN.
#
# What it checks (read-only, nothing is installed or modified):
#   1. Host      every php binary found (system, /opt, Plesk, sury, Remi,
#                LiteSpeed), distro packages (deb/rpm/apk incl. backport
#                changelogs), and PHP/Apache processes still running a
#                replaced binary (via /proc)
#   2. Docker    running containers exposing a PHP interpreter, floating
#                image tags, basic Swarm service convergence
#   3. SSH fleet read-only POSIX probe piped to each target listed in
#                servers.txt (or given via --ssh)
#   4. Shell access  after a scan it can drop you into a local remediation
#                shell or an ssh session on a flagged host (menu [7] or the
#                post-scan prompt) - using YOUR credentials only; it never
#                exploits the CVE and changes nothing on its own
#
# Verdict markers:  [OK]  fixed   [VULN] vulnerable   [??] unknown / n.a.
# Exit codes:       0 = all patched, 1 = at least one VULN, 2 = unknowns only
#
# Usage:
#   ./php2shell-check.sh               interactive menu (stays open; 'q' or
#                                      Ctrl+C-backed out; nothing auto-runs)
#   ./php2shell-check.sh --once        one-shot full sweep (cron / CI friendly)
#   ./php2shell-check.sh --watch 300   full sweep, re-test every 300 s
#   ./php2shell-check.sh --once --json machine-readable findings on stdout
#   ./php2shell-check.sh --ssh ops@web-01,web-02   probe remote targets
#   ./php2shell-check.sh --selftest    verify the version-verdict engine
#
# Output goes to your terminal (colored) AND to a timestamped log file
# (default /var/log/php2shell-check.log when writable, otherwise ./) so you
# can diff before/after a fix. Use --log FILE to choose the log path.
#
# Authorized use on systems you own or are licensed to test.
#===============================================================================

set -u
export LC_ALL=C

#--------------------------------- constants ---------------------------------
readonly PROGNAME="php2shell-check"
readonly VERSION="1.1.1"
readonly CVE_LABEL="php2shell (CVE-2026-109618 / CVE-2026-109619)"
readonly ADVISORY_DATE="2026-10-21"
readonly UP_INI="session.upload_progress.enabled"

# First fixed upstream release per maintained branch
declare -A FIXED=(
  ["8.2"]="8.2.35"
  ["8.3"]="8.3.36"
  ["8.4"]="8.4.27"
  ["8.5"]="8.5.12"
)
readonly EOL_NOTE="branches <= 8.1 are end-of-life and will never receive a fix"

#--------------------------------- state -------------------------------------
USE_COLOR="auto"          # auto | on | off
JSON_OUT=0
ONESHOT=0
MENU=0
WATCH_MODE=0
INTERVAL=300
LOG_FILE=""
SERVERS_FILE=""
SSH_TARGETS=()
RUN_DOCKER=1
SELFTEST=0
TARGET="$(hostname 2>/dev/null || echo localhost)"
LAST_SCAN="full"          # last menu scan type (for the post-fix re-check)
FLEET_VULN=()             # ssh targets flagged VULN by the most recent scan
LOCAL_HINTS=()            # de-duplicated fix hints from local VULN findings

WORST=0                   # 0 ok | 1 vuln | 2 unknown
FINDINGS=()               # target|component|detail|version|verdict|reason|hint
LAST_WORST=0

#--------------------------------- colors ------------------------------------
C_RED=""; C_GRN=""; C_YEL=""; C_CYA=""; C_DIM=""; C_BLD=""; NC=""

init_colors() {
  local want=0
  case "$USE_COLOR" in
    on)  want=1 ;;
    off) want=0 ;;
    auto) if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then want=1; else want=0; fi ;;
  esac
  if [ "$want" -eq 1 ]; then
    C_RED=$'\033[1;31m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'
    C_CYA=$'\033[1;36m'; C_DIM=$'\033[2m';   C_BLD=$'\033[1m'
    NC=$'\033[0m'
  fi
}

#--------------------------------- logging -----------------------------------
# Every message: colored marker on stdout (suppressed in --json mode so that
# stdout is pure JSON) + plain timestamped line appended to $LOG_FILE.
log_open() {
  if [ -z "$LOG_FILE" ]; then
    if { : >> /var/log/php2shell-check.log; } 2>/dev/null; then
      LOG_FILE="/var/log/php2shell-check.log"
    else
      LOG_FILE="${TMPDIR:-/tmp}/php2shell-check-$(date +%Y%m%d-%H%M%S).log"
      { : >> "$LOG_FILE"; } 2>/dev/null || LOG_FILE=""
    fi
  else
    { : >> "$LOG_FILE"; } 2>/dev/null || LOG_FILE=""
  fi
}

logline() { # $@ = plain text
  [ -n "$LOG_FILE" ] || return 0
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE"
}

_emit() { # $1=marker $2=color $@=text
  local marker="$1" color="$2"; shift 2
  logline "[$marker] $*"
  [ "$JSON_OUT" -eq 1 ] && return 0
  printf '%s[%s]%s %s\n' "$color" "$marker" "$NC" "$*"
}
ok()   { _emit OK   "$C_GRN" "$@"; }
vuln() { _emit VULN "$C_RED" "$@"; }
unk()  { _emit "??"  "$C_YEL" "$@"; }
info() { _emit i    "$C_CYA" "$@"; }
note() { _emit "-"   "$C_DIM" "$@"; }

section() {
  [ "$JSON_OUT" -eq 1 ] && return 0
  printf '\n%s== %s ==%s\n' "$C_BLD" "$*" "$NC"
  logline "==== $* ===="
}

#--------------------------------- findings ----------------------------------
# $1=target $2=component $3=detail $4=version $5=verdict $6=reason $7=hint
find_verdict() {
  local target="$1" comp="$2" det="$3" ver="$4" verdict="$5" reason="$6" hint="$7"
  FINDINGS+=("${target}|${comp}|${det}|${ver}|${verdict}|${reason}|${hint}")
  case "$verdict" in
    VULN)
      vuln "${comp}${det:+ [$det]}: ${ver} - ${reason}"
      [ -n "$hint" ] && note "  fix -> ${hint}"
      WORST=1
      ;;
    OK)
      ok "${comp}${det:+ [$det]}: ${ver} - ${reason}"
      ;;
    *)
      unk "${comp}${det:+ [$det]}: ${ver} - ${reason}"
      [ -n "$hint" ] && note "  hint -> ${hint}"
      [ "$WORST" -ne 1 ] && WORST=2
      ;;
  esac
}

#--------------------------- version verdict engine --------------------------
upstream_ver() { # strip epoch/distro suffix -> "8.3.36" ("" if unparseable)
  local v="${1#*:}"          # drop debian epoch "2:8.x.y"
  printf '%s' "$v" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

parse_php_version() { # $1 -> PV_M PV_N PV_P PV_SUF ; rc 1 if unparseable
  PV_SUF=""
  local v="$1" rest
  [ -n "$v" ] || return 1
  case "$v" in
    *.*.*)
      PV_M="${v%%.*}"; rest="${v#*.}"
      PV_N="${rest%%.*}"; rest="${rest#*.}"
      PV_P="${rest%%[!0-9]*}"
      PV_SUF="${rest#"${PV_P}"}"
      ;;
    *) return 1 ;;
  esac
  case "${PV_M}${PV_N}${PV_P}" in *[!0-9]*|"") return 1 ;; esac
  [ -n "$PV_M" ] && [ -n "$PV_N" ] && [ -n "$PV_P" ] || return 1
  return 0
}

# Sets VV_VERDICT (OK|VULN|UNKNOWN), VV_REASON, VV_HINT from a raw upstream
# version string. Pure function -> also used by --selftest.
verdict_for_version() {
  VV_HINT=""
  if ! parse_php_version "$1"; then
    VV_VERDICT="UNKNOWN"; VV_REASON="unparseable PHP version '$1'"; return 0
  fi
  if [ -n "$PV_SUF" ]; then
    VV_VERDICT="UNKNOWN"
    VV_REASON="pre-release / development build '$1' - not a fixed security release"
    VV_HINT="Install an official release (see php.net advisory of ${ADVISORY_DATE})."
    return 0
  fi
  local branch="${PV_M}.${PV_N}" fixed fp
  if [ "$PV_M" -lt 8 ] || { [ "$PV_M" -eq 8 ] && [ "$PV_N" -le 1 ]; }; then
    VV_VERDICT="VULN"
    VV_REASON="PHP ${branch} is end-of-life; ${CVE_LABEL} will never be fixed there"
    VV_HINT="Migrate to a maintained branch (8.3+ recommended). No patch exists for ${branch}."
    return 0
  fi
  fixed="${FIXED[$branch]:-}"
  if [ -z "$fixed" ]; then
    VV_VERDICT="UNKNOWN"
    VV_REASON="branch ${branch} is not in the fix table (newer than 8.5?)"
    VV_HINT="Verify against the official php.net security advisory."
    return 0
  fi
  local ip="$PV_P"   # installed patch (saved before parse_php_version overwrites it)
  parse_php_version "$fixed" || { VV_VERDICT="UNKNOWN"; VV_REASON="internal: bad fixed-version entry"; return 0; }
  fp="$PV_P"
  if [ "$ip" -ge "$fp" ]; then
    VV_VERDICT="OK"
    VV_REASON="upstream fix present: $1 >= ${fixed}"
  else
    VV_VERDICT="VULN"
    VV_REASON="installed $1 predates the fix (${fixed})"
    VV_HINT="Upgrade to ${fixed} (or newer) and restart the PHP service(s)."
  fi
  return 0
}

#----------------------------- JSON helpers ----------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\t'/ }"; s="${s//$'\n'/ }"; s="${s//$'\r'/ }"
  printf '"%s"' "$s"   # emits a complete, quoted JSON string
}

print_json() {
  local n_ok=0 n_v=0 n_u=0 f verdict
  local out
  out="{\"tool\":\"${PROGNAME}\",\"version\":\"${VERSION}\","
  out+="\"cves\":$(json_escape "$CVE_LABEL"),"
  out+="\"advisory_date\":\"${ADVISORY_DATE}\","
  out+="\"fixed_versions\":{\"8.2\":\"8.2.35\",\"8.3\":\"8.3.36\",\"8.4\":\"8.4.27\",\"8.5\":\"8.5.12\"},"
  out+="\"generated\":\"$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')\","
  out+="\"scan_target\":$(json_escape "$TARGET"),"
  out+="\"findings\":["
  local first=1
  for f in "${FINDINGS[@]:-}"; do
    [ -n "$f" ] || continue
    local -a _F=()
    IFS='|' read -r -a _F <<< "$f" || true
    local ftgt="${_F[0]:-}" fcomp="${_F[1]:-}" fdet="${_F[2]:-}" fver="${_F[3]:-}" fverdict="${_F[4]:-}" freason="${_F[5]:-}" fhint="${_F[6]:-}"
    [ "$first" -eq 1 ] || out+=","
    first=0
    out+="{\"target\":$(json_escape "$ftgt")"
    out+=",\"component\":$(json_escape "$fcomp")"
    out+=",\"detail\":$(json_escape "$fdet")"
    out+=",\"version\":$(json_escape "$fver")"
    out+=",\"verdict\":\"$fverdict\""
    out+=",\"reason\":$(json_escape "$freason")"
    out+=",\"hint\":$(json_escape "$fhint")}"
    case "$fverdict" in
      OK) n_ok=$((n_ok+1)) ;; VULN) n_v=$((n_v+1)) ;; *) n_u=$((n_u+1)) ;;
    esac
  done
  out+="],\"summary\":{\"ok\":$n_ok,\"vuln\":$n_v,\"unknown\":$n_u,\"exit_code\":$WORST}}"
  printf '%s\n' "$out"
}

#--------------------------------- selftest ----------------------------------
selftest() {
  local fail=0
  t() { # $1 expected  $2 version
    verdict_for_version "$2"
    if [ "$VV_VERDICT" != "$1" ]; then
      printf 'FAIL: %-12s expected %-8s got %s\n' "$2" "$1" "$VV_VERDICT"; fail=1
    else
      printf 'PASS: %-12s -> %s\n' "$2" "$VV_VERDICT"
    fi
  }
  echo "selftest: version verdict engine (${ADVISORY_DATE} fix table)"
  t OK      8.5.12;  t VULN    8.5.11;  t OK      8.5.13
  t OK      8.4.27;  t VULN    8.4.26
  t OK      8.3.36;  t VULN    8.3.35;  t OK      8.3.40
  t OK      8.2.35;  t VULN    8.2.34
  t VULN    8.1.31;  t VULN    8.0.30;  t VULN    7.4.33;  t VULN    5.6.40
  t UNKNOWN 8.3.0RC1; t UNKNOWN 8.3.37-dev; t UNKNOWN 9.0.0
  t UNKNOWN "";       t UNKNOWN not-a-version
  if [ "$fail" -eq 0 ]; then echo "selftest: ALL PASS"; return 0; fi
  echo "selftest: FAILURES PRESENT"; return 1
}

#============================== 1. HOST CHECKS ===============================
check_host_binaries() {
  section "host: PHP binaries on ${TARGET}"
  local -a seen=()
  local p rp vline v uv up extra
  # shellcheck disable=SC2043
  for p in \
      "$(command -v php 2>/dev/null)" \
      /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php /usr/local/bin/php[0-9]* \
      /usr/sbin/php-fpm* /usr/sbin/php[0-9]* \
      /opt/*/bin/php /opt/php*/bin/php /opt/plesk/php/*/bin/php \
      /usr/local/psa/bin/php /usr/local/lsws/lsphp*/bin/php /snap/bin/php* ; do
    [ -n "$p" ] || continue
    [ -f "$p" ] && [ -x "$p" ] || continue
    case "$p" in *"*\**") continue ;; esac   # unmatched glob left literal
    rp="$(readlink -f "$p" 2>/dev/null || printf '%s' "$p")"
    case " ${seen[*]-} " in *" ${rp} "*) continue ;; esac
    seen+=("$rp")

    vline="$("$rp" -v 2>/dev/null | head -n1)"
    case "$vline" in
      PHP\ *) v="$(printf '%s' "$vline" | awk '{print $2}')" ;;
      HipHop*)
        find_verdict "$TARGET" "HHVM binary ${rp}" "" "?" UNKNOWN \
          "HHVM is not PHP core; ${CVE_LABEL} does not apply (assess HHVM separately)" ""
        continue ;;
      *) continue ;;
    esac
    [ -n "$v" ] || continue
    uv="$(upstream_ver "$v")"; [ -n "$uv" ] || uv="$v"
    verdict_for_version "$uv"

    # exposure-mechanism status (session.upload_progress must be enabled for
    # the known attack path; disabling is interim hardening only)
    up="$("$rp" -r "echo (int)ini_get('${UP_INI}');" 2>/dev/null)"
    extra=""
    [ "$up" = "1" ] && extra="; ${UP_INI}=1 (attack mechanism enabled)"
    find_verdict "$TARGET" "PHP CLI/CGI ${rp}" "" "$v" "$VV_VERDICT" "$VV_REASON${extra}" "$VV_HINT"
    if [ "$VV_VERDICT" = "VULN" ] && [ "$up" = "1" ]; then
      note "  interim: set ${UP_INI} = 0 in this SAPI's php.ini (hardening, NOT a substitute for the upgrade)"
    fi
  done
  if [ "${#seen[@]}" -eq 0 ]; then
    info "no PHP binary found on this host (PHP may run only inside containers -> see docker section)"
  fi
}

check_host_packages() {
  section "host: distro PHP packages (${TARGET})"
  local mgr=""
  if command -v dpkg-query >/dev/null 2>&1; then mgr="deb"
  elif command -v rpm >/dev/null 2>&1; then mgr="rpm"
  elif command -v apk >/dev/null 2>&1; then mgr="apk"
  else
    info "no dpkg/rpm/apk backend found - skipping distro package check"
    return 0
  fi

  # per-branch aggregation: BR_VER[branch]=installed-version  BR_PKGS[branch]="pkgs"
  declare -A BR_VER=() BR_PKGS=()
  local pkg ver branch uv

  if [ "$mgr" = "deb" ]; then
    local status
    while IFS=$'\t' read -r pkg ver status; do
      [ "${status:0:2}" = "ii" ] || continue
      case "$pkg" in php*|libapache2-mod-php*|libphp*) ;; *) continue ;; esac
      uv="$(upstream_ver "$ver")"
      branch=""
      case "$pkg" in
        php[0-9].[0-9]*|libapache2-mod-php[0-9].[0-9]*)
          branch="$(printf '%s' "$pkg" | grep -oE '[0-9]+\.[0-9]+' | head -n1)" ;;
      esac
      [ -n "$branch" ] || { [ -n "$uv" ] && branch="${uv%.*}"; }
      [ -n "$branch" ] || continue
      [ -n "${BR_VER[$branch]:-}" ] || BR_VER["$branch"]="$ver"
      BR_PKGS["$branch"]="${BR_PKGS[$branch]:-} $pkg"
    done < <(dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' \
               'php*' 'libapache2-mod-php*' 2>/dev/null)

  elif [ "$mgr" = "rpm" ]; then
    while IFS=$'\t' read -r pkg ver; do
      uv="$(upstream_ver "$ver")"
      branch=""
      case "$pkg" in
        php[0-9][0-9]-*)                       # Remi multi-version: php83-php-*
          local d="${pkg#php}"; d="${d%%-*}"
          branch="${d:0:1}.${d:1:1}" ;;
        php*|libphp*) branch="" ;;
        *) continue ;;
      esac
      [ -n "$branch" ] || { [ -n "$uv" ] && branch="${uv%.*}"; }
      [ -n "$branch" ] || continue
      [ -n "${BR_VER[$branch]:-}" ] || BR_VER["$branch"]="$ver"
      BR_PKGS["$branch"]="${BR_PKGS[$branch]:-} $pkg"
    done < <(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | awk -F'\t' '$1 ~ /^php|^libphp/')

  else # apk — Alpine ships upstream builds, version is authoritative
    while read -r ver; do
      uv="$(upstream_ver "$ver")"
      [ -n "$uv" ] || continue
      branch="${uv%.*}"
      [ -n "${BR_VER[$branch]:-}" ] || BR_VER["$branch"]="$ver"
      BR_PKGS["$branch"]="${BR_PKGS[$branch]:-} ${ver%%-*}"
    done < <(apk info -v 2>/dev/null | awk '$1 ~ /^php/ {print $1}')
  fi

  if [ "${#BR_VER[@]}" -eq 0 ]; then
    info "no PHP distro packages installed via ${mgr}"
    return 0
  fi

  local fixed pkgs chlog backported
  for branch in "${!BR_VER[@]}"; do
    ver="${BR_VER[$branch]}"
    pkgs="$(printf '%s' "${BR_PKGS[$branch]}" | awk '{print NF" pkg(s):"$0}')"
    uv="$(upstream_ver "$ver")"; [ -n "$uv" ] || uv=""
    fixed="${FIXED[$branch]:-}"

    if [ -n "$uv" ] && [ -n "$fixed" ]; then
      verdict_for_version "$uv"
      # Debian/Ubuntu/RHEL may backport without bumping upstream version:
      # prove it from the changelog; sury/remi/alpine ship upstream versions.
      backported=0
      if [ "$VV_VERDICT" = "VULN" ] && [ "$mgr" != "apk" ] \
         && ! printf '%s' "$ver" | grep -Eq 'sury|remi'; then
        if [ "$mgr" = "deb" ]; then
          chlog="$(ls /usr/share/doc/php${branch}-common/changelog.Debian*.gz 2>/dev/null | head -n1)"
          [ -n "$chlog" ] && zcat "$chlog" 2>/dev/null | grep -qE 'CVE-2026-10961[89]' && backported=1
        else
          for _p in ${BR_PKGS[$branch]}; do
            rpm -q --changelog "$_p" 2>/dev/null | grep -qE 'CVE-2026-10961[89]' && { backported=1; break; }
          done
        fi
        if [ "$backported" -eq 1 ]; then
          VV_VERDICT="OK"
          VV_REASON="distro backport confirmed: changelog cites CVE-2026-109618/109619 (build ${ver})"
          VV_HINT=""
        else
          VV_VERDICT="VULN"
          VV_REASON="distro build ${ver} (upstream ${uv}) predates fix ${fixed}; no backport found in changelog"
          VV_HINT="$(fix_hint_for_branch "$mgr" "$branch")"
        fi
      fi
      find_verdict "$TARGET" "pkg${pkgs}" "" "$ver" "$VV_VERDICT" "$VV_REASON" "$VV_HINT"
    else
      find_verdict "$TARGET" "pkg${pkgs}" "" "$ver" UNKNOWN \
        "could not derive an upstream version/branch from '${ver}'" \
        "check the distro security tracker for ${CVE_LABEL}"
    fi
  done
}

fix_hint_for_branch() { # $1=mgr $2=branch -> concrete upgrade/restart command
  local mgr="$1" branch="$2" digits
  digits="$(printf '%s' "$branch" | tr -d '.')"
  case "$mgr" in
    deb) echo "sudo apt update && sudo apt install --only-upgrade 'php${branch}*' && sudo systemctl restart php${branch}-fpm apache2 2>/dev/null" ;;
    rpm) echo "sudo dnf update 'php*' && sudo systemctl restart php-fpm httpd" ;;
    apk) echo "sudo apk add --upgrade php${digits} php${digits}-fpm && sudo rc-service php-fpm${digits} restart" ;;
    *)   echo "upgrade PHP >= ${FIXED[$branch]:-the fixed release} and restart PHP services" ;;
  esac
}

check_running_processes() {
  section "host: processes still running a replaced binary (/proc) - ${TARGET}"
  [ "$(id -u)" -eq 0 ] || note "not running as root: some /proc entries may be unreadable (rerun with sudo for full coverage)"

  local pids pid exe p
  # prefix regex (not -x): catches versioned process names like php-fpm8.2
  # (Debian/Ubuntu/sury) and php-fpm82 (Alpine), not just plain "php-fpm"
  pids="$( { pgrep '^php-fpm'; pgrep '^php-cgi'; pgrep '^frankenphp'; \
             pgrep -x apache2;  pgrep '^httpd'; } 2>/dev/null | sort -un )"
  if [ -z "$pids" ]; then
    info "no running php-fpm / php-cgi / FrankenPHP / Apache processes found"
    return 0
  fi

  local clean=0 noperm=0 libphp_bad=0
  local -A del_paths=()
  for pid in $pids; do
    exe="$(readlink "/proc/${pid}/exe" 2>/dev/null)"
    if [ -z "$exe" ]; then noperm=$((noperm+1)); continue; fi
    if [ "${exe% (deleted)}" != "$exe" ]; then
      p="${exe% (deleted)}"
      del_paths["$p"]="${del_paths["$p"]:-} ${pid}"
    else
      clean=$((clean+1))
    fi
    # mod_php: the web server binary itself is fine, but a replaced libphp .so
    # mapped into the process means the patch is not loaded
    if grep -q 'libphp' "/proc/${pid}/maps" 2>/dev/null; then
      if grep 'libphp' "/proc/${pid}/maps" 2>/dev/null | grep -q '(deleted)'; then
        libphp_bad=$((libphp_bad+1))
      fi
    fi
  done

  for p in "${!del_paths[@]}"; do
    find_verdict "$TARGET" "running process (${p})" "pids:${del_paths[$p]}" "old binary" VULN \
      "binary was replaced on disk but this process still executes the pre-patch code" \
      "sudo systemctl restart php*-fpm apache2 2>/dev/null (or reboot) to load the patched binary"
  done
  [ "$libphp_bad" -gt 0 ] && \
    find_verdict "$TARGET" "Apache mod_php" "${libphp_bad} process(es)" "old libphp.so" VULN \
      "Apache still maps the pre-patch libphp module" \
      "sudo systemctl restart apache2 (or httpd) to load the patched module"
  [ "$clean" -gt 0 ] && \
    ok "running processes: ${clean} PHP/web-server process(es) checked, current binaries"
  if [ "$noperm" -gt 0 ] && [ "$clean" -eq 0 ] && [ "${#del_paths[@]}" -eq 0 ]; then
    unk "could not inspect ${noperm} PHP/web-server process(es) (permission denied)"
    note "  hint -> rerun with sudo for a definitive /proc verdict"
  fi
  return 0
}

#============================== 2. DOCKER CHECKS =============================
check_docker() {
  [ "$RUN_DOCKER" -eq 1 ] || return 0
  section "docker: containers and swarm - ${TARGET}"
  command -v docker >/dev/null 2>&1 || { info "docker CLI not found - skipping container checks"; return 0; }
  docker version >/dev/null 2>&1 || {
    unk "docker installed but the daemon is not reachable (permissions?)"
    note "  hint -> run with sudo, or add your user to the docker group"
    return 0
  }

  local cid img name v found=0 uv tagnote
  while IFS=$'\t' read -r cid img name; do
    [ -n "$cid" ] || continue
    v="$(timeout 15 docker exec "$cid" sh -c 'command -v php >/dev/null 2>&1 && php -r "echo PHP_VERSION;"' 2>/dev/null)"
    [ -n "$v" ] || continue
    found=1
    uv="$(upstream_ver "$v")"; [ -n "$uv" ] || uv="$v"
    verdict_for_version "$uv"
    tagnote=""
    case "$img" in
      *@sha256:*) ;;
      *) tagnote="; floating tag '${img}' only picks the fix after a rebuild ('docker build --pull' / pull fresh image) and redeploy" ;;
    esac
    find_verdict "$TARGET" "container ${name} (image ${img})" "$cid" "$v" "$VV_VERDICT" "$VV_REASON${tagnote}" "$VV_HINT"
  done < <(docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}' 2>/dev/null)
  [ "$found" -eq 1 ] || info "no running container exposes a PHP interpreter"

  # swarm convergence (coarse): flag php-ish services with non-running tasks
  if docker service ls >/dev/null 2>&1; then
    local svc simg bad
    while IFS=$'\t' read -r svc simg; do
      [ -n "$svc" ] || continue
      case "$simg" in *php*|*wordpress*) ;; *) continue ;; esac
      bad="$(docker service ps --format '{{.DesiredState}} {{.CurrentState}} {{.Image}}' "$svc" 2>/dev/null \
             | awk '$1 != "running" {print; c++} c>=3{exit}')"
      if [ -n "$bad" ]; then
        unk "swarm service ${svc} (image ${simg}) has non-converged tasks"
        note "  hint -> inspect with: docker service ps ${svc} --no-trunc ; reconcile/roll the service manually"
      else
        ok "swarm service ${svc}: all tasks running (image ${simg})"
      fi
    done < <(docker service ls --format '{{.Name}}\t{{.Image}}' 2>/dev/null)
  fi
  return 0
}

#============================== 3. SSH FLEET =================================
ssh_probe() { # $1=ssh target ; read-only POSIX probe, nothing installed
  ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new \
      "$1" 'sh -s' <<'PROBE'
. /etc/os-release 2>/dev/null
echo "OS|${ID:-unknown}|${VERSION_ID:-unknown}"
for b in "$(command -v php 2>/dev/null)" \
         /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php /usr/local/bin/php[0-9]* \
         /usr/sbin/php-fpm[0-9]* /opt/plesk/php/*/bin/php /usr/local/lsws/lsphp*/bin/php ; do
  [ -n "$b" ] || continue
  [ -f "$b" ] && [ -x "$b" ] || continue
  case "$b" in *"*\**") continue ;; esac
  v="$("$b" -v 2>/dev/null | head -n 1)"
  case "$v" in "PHP "*) v="$(echo "$v" | awk '{print $2}')" ;; *) continue ;; esac
  up="$("$b" -r 'echo (int)ini_get("session.upload_progress.enabled");' 2>/dev/null)"
  echo "BIN|$b|${v:-?}|${up:-?}"
done
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${binary:Package}|${Version}\n' 2>/dev/null \
    | awk -F'|' '$1 ~ /^php|^libphp/ {printf "PKG|deb|%s|%s\n", $1, $2}'
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME}|%{VERSION}\n' 2>/dev/null \
    | awk -F'|' '$1 ~ /^php|^libphp/ {printf "PKG|rpm|%s|%s\n", $1, $2}'
elif command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | awk '$1 ~ /^php/ {printf "PKG|apk|%s|\n", $1}'
fi
echo "DONE"
PROBE
}

# fleet policy: a remote runtime is judged by upstream version; a maintained
# branch that merely predates the fix stays UNKNOWN (the distro may have
# backported the fix without changing the version) until checked on the host.
fleet_verdict() { # reuses VV_* from verdict_for_version
  if [ "$VV_VERDICT" = "VULN" ] && ! printf '%s' "$VV_REASON" | grep -q 'end-of-life'; then
    VV_VERDICT="UNKNOWN"
    VV_REASON="remote upstream version predates the fix; a distro backport is possible"
    VV_HINT="verify on that host: ssh <target> 'sudo bash -s' < $(printf '%s' "${0:-php2shell-check.sh}") --once"
  fi
}

check_fleet() {
  section "ssh fleet: remote targets"
  local -a targets=()
  if [ "${#SSH_TARGETS[@]}" -gt 0 ]; then targets+=("${SSH_TARGETS[@]}"); fi
  if [ -n "$SERVERS_FILE" ] && [ -f "$SERVERS_FILE" ]; then
    local line
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%%#*}"
      line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
      [ -n "$line" ] || continue
      case " ${targets[*]-} " in *" ${line} "*) continue ;; esac
      targets+=("$line")
    done < "$SERVERS_FILE"
  fi
  if [ "${#targets[@]}" -eq 0 ]; then
    info "no SSH targets (create servers.txt next to this script, or pass --ssh host1,host2)"
    return 0
  fi

  local t out line _tag rpath rver rup ruv rbranch rmgr rpkg
  for t in "${targets[@]}"; do
    info "probing ${t} ..."
    out="$(ssh_probe "$t" 2>/dev/null)" || {
      unk "ssh target ${t}: unreachable or probe failed"
      note "  hint -> check key-based ssh access (BatchMode was used)"
      continue;
    }
    local -a pkg_seen=()
    while IFS= read -r line; do
      case "$line" in
        OS\|*) note "  ${t}: ${line#OS|}" ;;
        BIN\|*)
          IFS='|' read -r rpath rver rup <<< "${line#BIN|}"
          [ -n "$rver" ] && [ "$rver" != "?" ] || continue
          ruv="$(upstream_ver "$rver")"; [ -n "$ruv" ] || ruv="$rver"
          verdict_for_version "$ruv"; fleet_verdict
          find_verdict "$t" "remote PHP ${rpath}" "" "$rver" "$VV_VERDICT" "$VV_REASON" "$VV_HINT"
          ;;
        PKG\|*)
          IFS='|' read -r rmgr rpkg rver <<< "${line#PKG|}"
          ruv="$(upstream_ver "$rver")"; [ -n "$ruv" ] || continue
          rbranch="${ruv%.*}"
          case " ${pkg_seen[*]-} " in *" ${rbranch} "*) continue ;; esac
          pkg_seen+=("$rbranch")
          verdict_for_version "$ruv"; fleet_verdict
          find_verdict "$t" "remote pkg(${rmgr}) branch ${rbranch}" "" "$rver" "$VV_VERDICT" "$VV_REASON" "$VV_HINT"
          ;;
        DONE) break ;;
      esac
    done <<< "$out"
  done
  return 0
}

#============================== SUMMARY ======================================
summarize() {
  local n_ok=0 n_v=0 n_u=0 f v5
  for f in "${FINDINGS[@]:-}"; do
    [ -n "$f" ] || continue
    IFS='|' read -r _a _b _c _d v5 _ <<< "$f"
    case "$v5" in OK) n_ok=$((n_ok+1)) ;; VULN) n_v=$((n_v+1)) ;; *) n_u=$((n_u+1)) ;; esac
  done
  section "summary - ${TARGET}"
  if [ $((n_ok + n_v + n_u)) -eq 0 ]; then
    info "no PHP runtime found to judge on this scope"
    LAST_WORST=0
    return 0
  fi
  info "verdicts: ${n_ok} OK / ${n_v} VULN / ${n_u} unknown   (log: ${LOG_FILE:-none})"
  if [ "$n_v" -gt 0 ]; then
    vuln "RESULT: VULNERABLE - upgrade PHP, RESTART the services, then re-run this check (exit 1)"
    note "  reminder: an upgraded-but-unrestarted php-fpm/Apache is still exploitable"
  elif [ "$n_u" -gt 0 ]; then
    unk "RESULT: INCOMPLETE - resolve the unknowns above (exit 2)"
  else
    ok "RESULT: ALL CLEAR - every PHP runtime found is fixed for ${CVE_LABEL} (exit 0)"
  fi
  LAST_WORST=$WORST
}

#============================== SWEEP WRAPPERS ===============================
sweep_header() {
  WORST=0; FINDINGS=()
  logline "=================================================================="
  logline "php2shell-check run @ $(date '+%Y-%m-%d %H:%M:%S') | host=${TARGET} | user=$(id -un 2>/dev/null)"
  note "target: ${CVE_LABEL} | fixed upstream in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (php.net ${ADVISORY_DATE})"
  note "${EOL_NOTE}; an upgraded-but-unrestarted runtime is still vulnerable"
}

run_host()      { sweep_header; check_host_binaries;    check_host_packages; check_running_processes; summarize; }
run_docker()    { sweep_header; check_docker;           summarize; }
run_fleet()     { sweep_header; check_fleet;            summarize; }
run_full_sweep(){ sweep_header; check_host_binaries;    check_host_packages; check_running_processes; check_docker; check_fleet; summarize; }

#============================== WATCH MODE ===================================
watch_mode() {
  while true; do
    run_full_sweep
    [ "$JSON_OUT" -eq 1 ] && print_json
    info "next re-test in ${INTERVAL}s (press Ctrl+C to stop)"
    local sleeper=0
    trap 'sleeper=1; break' INT
    sleep "$INTERVAL" &
    wait $! 2>/dev/null
    trap - INT
    [ "$sleeper" -eq 1 ] && break
  done
  info "watch stopped - last result kept in the log (${LOG_FILE:-none})"
}

#============================== SHELL ACCESS ==================================
# Post-scan access helpers (interactive menu only). They open shells with YOUR
# OWN credentials only - a local login shell, or ssh with your keys/agent -
# so a flagged fix can be applied immediately, then re-checked. The checker
# itself stays read-only: it never exploits the CVE and changes nothing.

collect_flagged() { # fill FLEET_VULN (ssh targets) + LOCAL_HINTS (fix hints)
  local f tgt comp verdict hint dup h t
  FLEET_VULN=(); LOCAL_HINTS=()
  for f in "${FINDINGS[@]:-}"; do
    [ -n "$f" ] || continue
    IFS='|' read -r tgt comp _ _ verdict _ hint <<< "$f" || true
    [ "$verdict" = "VULN" ] || continue
    dup=0
    case "$comp" in
      remote\ *)
        for t in "${FLEET_VULN[@]:-}"; do [ "$t" = "$tgt" ] && { dup=1; break; }; done
        [ "$dup" -eq 1 ] || FLEET_VULN+=("$tgt") ;;
      *)
        [ -n "$hint" ] || continue
        for h in "${LOCAL_HINTS[@]:-}"; do [ "$h" = "$hint" ] && { dup=1; break; }; done
        [ "$dup" -eq 1 ] || LOCAL_HINTS+=("$hint") ;;
    esac
  done
  return 0
}

open_local_shell() { # interactive subshell here; prints the pending fix hints
  local sh="${SHELL:-}" i=1 h
  if [ -z "$sh" ] || [ ! -x "$sh" ]; then
    sh="$(command -v bash 2>/dev/null || command -v sh 2>/dev/null || printf '%s' /bin/sh)"
  fi
  section "remediation shell on ${TARGET} (${sh##*/})"
  if [ "${#LOCAL_HINTS[@]}" -gt 0 ]; then
    note "fix commands for the findings above (run them, then come back):"
    for h in "${LOCAL_HINTS[@]}"; do printf '  %d) %s\n' "$i" "$h"; i=$((i+1)); done
  else
    note "no pending fix hints - plain shell on ${TARGET}"
  fi
  note "type 'exit' or press Ctrl+D to return to the checker"
  logline "remediation subshell opened on ${TARGET} (user=$(id -un 2>/dev/null))"
  "$sh"
  info "remediation shell exited"
  logline "remediation subshell closed on ${TARGET}"
  note "re-run the check (menu [1] / [4]) to confirm the fix"
  return 0
}

open_ssh_session() { # $1 = ssh destination (same syntax as servers.txt lines)
  local t="$1"
  command -v ssh >/dev/null 2>&1 || { unk "no ssh client found - cannot open a remote session"; return 1; }
  info "connecting: ssh -t ${t}    (end the session with 'exit' to come back)"
  note "interactive session (no BatchMode): keys / agent / password all work"
  logline "interactive ssh session opened to ${t} (user=$(id -un 2>/dev/null))"
  ssh -t -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -- "$t"
  info "ssh session to ${t} closed"
  logline "interactive ssh session closed (${t})"
  return 0
}

reprobe_target() { # $1 = target; fleet re-scan scoped to that one host
  local t="$1" saved_srv="$SERVERS_FILE"
  local -a saved=()
  [ "${#SSH_TARGETS[@]}" -eq 0 ] || saved=("${SSH_TARGETS[@]}")
  SSH_TARGETS=("$t"); SERVERS_FILE=""
  run_fleet
  SERVERS_FILE="$saved_srv"
  SSH_TARGETS=()
  [ "${#saved[@]}" -eq 0 ] || SSH_TARGETS=("${saved[@]}")
  return 0
}

offer_after_scan() { # post-scan hook: fix flagged items via your own shell/ssh
  collect_flagged
  local ans t i
  if [ "${#FLEET_VULN[@]}" -gt 0 ]; then
    printf '%sflagged remote hosts:%s\n' "$C_YEL" "$NC"
    i=1; for t in "${FLEET_VULN[@]}"; do printf '  %d) %s\n' "$i" "$t"; i=$((i+1)); done
    printf 'open an ssh session on one to fix it? [number / N]: '
    IFS= read -r ans || ans=""
    case "$ans" in
      *[!0-9]*|'') : ;;
      *)
        ans=$((10#$ans))
        if [ "$ans" -ge 1 ] && [ "$ans" -le "${#FLEET_VULN[@]}" ]; then
          t="${FLEET_VULN[$((ans-1))]}"
          open_ssh_session "$t"
          printf 're-probe %s now to confirm the fix? [Y/n]: ' "$t"
          IFS= read -r ans || ans=""
          case "$ans" in n|N|no|NO) : ;; *) reprobe_target "$t" ;; esac
        else
          printf 'no such entry (1-%d)\n' "${#FLEET_VULN[@]}"
        fi ;;
    esac
    collect_flagged
  fi
  if [ "${#LOCAL_HINTS[@]}" -gt 0 ]; then
    printf 'open a local remediation shell on %s now? [y/N]: ' "$TARGET"
    IFS= read -r ans || ans=""
    case "$ans" in
      y|Y|yes|YES)
        open_local_shell
        printf 're-run the check now to confirm the fix? [Y/n]: '
        IFS= read -r ans || ans=""
        case "$ans" in
          n|N|no|NO) : ;;
          *) case "$LAST_SCAN" in
               host)   run_host ;;
               docker) run_docker ;;
               fleet)  run_fleet ;;
               *)      run_full_sweep ;;
             esac ;;
        esac ;;
    esac
  fi
  return 0
}

menu_shell_access() { # menu [7]: the same helpers, on demand
  collect_flagged
  local ans t h i
  printf '\n-- shell access (uses YOUR credentials; the checker never exploits the bug) --\n'
  if [ "${#FLEET_VULN[@]}" -eq 0 ] && [ "${#LOCAL_HINTS[@]}" -eq 0 ]; then
    info "nothing flagged VULN yet - run [1] host / [3] fleet / [4] full sweep first"
  fi
  if [ "${#FLEET_VULN[@]}" -gt 0 ]; then
    note "flagged remote hosts:"
    i=1; for t in "${FLEET_VULN[@]}"; do printf '  %2d) ssh %s\n' "$i" "$t"; i=$((i+1)); done
  fi
  if [ "${#LOCAL_HINTS[@]}" -gt 0 ]; then
    note "pending local fix hints on ${TARGET}:"
    for h in "${LOCAL_HINTS[@]}"; do printf '  -> %s\n' "$h"; done
  fi
  printf '  [1] open a local remediation shell on %s\n' "$TARGET"
  printf '  [2] ssh to a flagged remote host\n'
  printf '  [b] back\n'
  printf 'select> '
  IFS= read -r ans || return 0
  case "$ans" in
    1) open_local_shell ;;
    2)
      if [ "${#FLEET_VULN[@]}" -eq 0 ]; then
        info "no flagged remote host - scan the fleet first ([3] or [4])"
      else
        printf 'host number [1-%d]: ' "${#FLEET_VULN[@]}"
        IFS= read -r ans || return 0
        case "$ans" in
          *[!0-9]*|'') printf 'cancelled\n' ;;
          *)
            ans=$((10#$ans))
            if [ "$ans" -ge 1 ] && [ "$ans" -le "${#FLEET_VULN[@]}" ]; then
              t="${FLEET_VULN[$((ans-1))]}"
              open_ssh_session "$t"
              printf 're-probe %s now to confirm the fix? [Y/n]: ' "$t"
              IFS= read -r ans || ans=""
              case "$ans" in n|N|no|NO) : ;; *) reprobe_target "$t" ;; esac
            else
              printf 'no such entry (1-%d)\n' "${#FLEET_VULN[@]}"
            fi ;;
        esac
      fi ;;
    b|B) : ;;
    *) printf 'unknown choice: %s\n' "$ans" ;;
  esac
  return 0
}

#============================== INTERACTIVE MENU =============================
menu_banner() {
  [ -t 1 ] && printf '\033[H\033[2J\033[3J'
  printf '%sphp2shell-check v%s%s - %s\n' "$C_BLD" "$VERSION" "$NC" "$CVE_LABEL"
  printf 'fixed in: 8.2.35 | 8.3.36 | 8.4.27 | 8.5.12   (php.net release %s)\n' "$ADVISORY_DATE"
  printf 'log file   : %s\n' "${LOG_FILE:-<none>}"
  printf 'watch intv : %ss    docker checks: %s\n' "$INTERVAL" "$([ "$RUN_DOCKER" -eq 1 ] && echo on || echo off)"
  printf 'ssh targets: %s%s\n' "${SERVERS_FILE:-servers.txt}${SSH_TARGETS[*]:+ + ${SSH_TARGETS[*]}}" ""
  printf '%s-------------------------------------------------------------%s\n' "$C_DIM" "$NC"
  printf '  [1] check this host   (binaries + packages + running processes)\n'
  printf '  [2] check docker      (containers + swarm)\n'
  printf '  [3] check ssh fleet   (%s)\n' "${SERVERS_FILE:-servers.txt} / --ssh list"
  printf '  [4] full sweep        (1 + 2 + 3)\n'
  printf '  [5] watch mode        (re-test every %ss; Ctrl+C returns here)\n' "$INTERVAL"
  printf '  [6] settings          (interval / log file / servers file / docker)\n'
  printf '  [7] shell access      (local remediation shell / ssh to a flagged host)\n'
  printf '  [q] quit\n'
}

menu_settings() {
  printf '\n-- settings --\n'
  printf 'current: interval=%ss log=%s servers=%s docker=%s\n' \
    "$INTERVAL" "${LOG_FILE:-auto}" "${SERVERS_FILE:-servers.txt}" "$([ "$RUN_DOCKER" -eq 1 ] && echo on || echo off)"
  local ans
  printf 'new watch interval in seconds [%s]: ' "$INTERVAL"
  IFS= read -r ans && { case "$ans" in ''|*[!0-9]*) : ;; *) INTERVAL="$ans" ;; esac; }
  printf 'new log file path (empty = keep %s): ' "${LOG_FILE:-auto}"
  IFS= read -r ans && { [ -n "$ans" ] && { LOG_FILE="$ans"; log_open; }; }
  printf 'new servers.txt path [%s]: ' "${SERVERS_FILE:-servers.txt}"
  IFS= read -r ans && { [ -n "$ans" ] && SERVERS_FILE="$ans"; }
  printf 'toggle docker checks? y/N: '
  IFS= read -r ans && { case "$ans" in y|Y) RUN_DOCKER=0 ;; n|N|"") RUN_DOCKER=1 ;; esac; }
  printf 'settings saved for this session.\n'
}

menu() {
  trap 'printf "\n(use [q] to quit)\n"' INT
  local choice
  while true; do
    menu_banner
    printf 'select> '
    IFS= read -r choice || { printf '\n'; break; }
    case "$choice" in
      1) run_host;       LAST_SCAN="host";  offer_after_scan ;;
      2) run_docker;     LAST_SCAN="docker"; offer_after_scan ;;
      3) run_fleet;      LAST_SCAN="fleet"; offer_after_scan ;;
      4) run_full_sweep; LAST_SCAN="full";  offer_after_scan ;;
      5) watch_mode ;;
      6) menu_settings ;;
      7) menu_shell_access ;;
      q|Q) break ;;
      '') : ;;
      *) printf 'unknown choice: %s\n' "$choice" ;;
    esac
    [ "$choice" = "5" ] || { printf '\npress Enter to return to the menu... '; IFS= read -r _ || break; }
  done
  trap - INT
  info "bye - full history kept in ${LOG_FILE:-<no log>}"
}

#============================== CLI / MAIN ===================================
usage() {
  cat <<EOF
${PROGNAME} v${VERSION} - checker for ${CVE_LABEL}

Fixed upstream in the php.net release of ${ADVISORY_DATE}:
    8.2 -> 8.2.35    8.3 -> 8.3.36    8.4 -> 8.4.27    8.5 -> 8.5.12
    8.1 and older: end-of-life, no fix exists -> always [VULN].

Usage:
  ${PROGNAME}                    interactive menu (stays open; quit with [q])
  ${PROGNAME} --once             one-shot full sweep (cron/CI friendly)
  ${PROGNAME} --watch 300        sweep now, then re-test every 300 s (Ctrl+C stops)
  ${PROGNAME} --once --json      findings as JSON on stdout (exit code preserved)

Options:
  --ssh HOST[,HOST...]   probe remote targets over ssh (read-only, BatchMode)
  --servers FILE         ssh target list (default: servers.txt next to script)
  --log FILE             log file (default: /var/log/php2shell-check.log if
                         writable, else a timestamped file next to you)
  --interval SECONDS     watch-mode interval (default 300)
  --no-docker            skip docker checks
  --no-color / --color   force terminal colors off/on (default: auto)
  --selftest             verify the version-verdict engine and exit
  --help                 this text

Shell access (interactive menu only: [7], or answer the post-scan prompt):
  after a scan the checker can open a local remediation shell, or an ssh
  session on a flagged host, so you can apply the fix immediately and
  re-check. It uses your own login/ssh credentials - the checker never
  exploits the CVE itself.

Exit codes: 0 = all patched | 1 = at least one VULN | 2 = unknowns only
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --once|-1)      ONESHOT=1 ;;
      --menu)         MENU=1 ;;
      --json)         JSON_OUT=1 ;;
      --no-color)     USE_COLOR="off" ;;
      --color)        USE_COLOR="on" ;;
      --log)          [ $# -ge 2 ] && LOG_FILE="$2" && shift ;;
      --servers)      [ $# -ge 2 ] && SERVERS_FILE="$2" && shift ;;
      --ssh)          [ $# -ge 2 ] || { echo "--ssh needs a host list" >&2; exit 64; }
                      local -a _t=(); IFS=',' read -r -a _t <<< "$2"
                      local _x; for _x in "${_t[@]}"; do [ -n "$_x" ] && SSH_TARGETS+=("$_x"); done
                      shift ;;
      --watch)        WATCH_MODE=1
                      if [ $# -ge 2 ] && printf '%s' "$2" | grep -qE '^[0-9]+$'; then INTERVAL="$2"; shift; fi ;;
      --interval)     [ $# -ge 2 ] && printf '%s' "$2" | grep -qE '^[0-9]+$' && INTERVAL="$2" && shift ;;
      --no-docker)    RUN_DOCKER=0 ;;
      --selftest)     SELFTEST=1 ;;
      --help|-h)      usage; exit 0 ;;
      --)             shift; break ;;
      -*)             echo "unknown option: $1" >&2; usage; exit 64 ;;
      *)              echo "unexpected argument: $1" >&2; usage; exit 64 ;;
    esac
    shift
  done
}

main() {
  if [ -z "${BASH_VERSION:-}" ] || [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    echo "error: bash >= 4 is required" >&2
    exit 64
  fi
  parse_args "$@"
  [ "$MENU" -eq 1 ] && JSON_OUT=0
  init_colors

  if [ "$SELFTEST" -eq 1 ]; then
    selftest
    exit $?
  fi

  # default servers.txt: next to the script, else ./servers.txt
  if [ -z "$SERVERS_FILE" ]; then
    local dir="${0%/*}"
    [ -f "${dir}/servers.txt" ] && SERVERS_FILE="${dir}/servers.txt"
    [ -f "servers.txt" ] && [ -z "$SERVERS_FILE" ] && SERVERS_FILE="servers.txt"
  fi

  log_open

  if [ "$MENU" -eq 1 ] || { [ "$ONESHOT" -eq 0 ] && [ "$WATCH_MODE" -eq 0 ] && [ -t 0 ] && [ -t 1 ]; }; then
    menu
    exit 0
  fi

  if [ "$WATCH_MODE" -eq 1 ]; then
    run_full_sweep
    watch_mode
    exit "$LAST_WORST"
  fi

  run_full_sweep
  [ "$JSON_OUT" -eq 1 ] && print_json
  exit "$WORST"
}

main "$@"
