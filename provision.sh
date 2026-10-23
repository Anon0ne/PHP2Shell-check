#!/usr/bin/env bash
#===============================================================================
# provision.sh — php2shell-lab guest bootstrap (runs as root inside the VM,
#                invoked automatically by the Vagrantfile shell provisioner).
#
# Builds a deliberately-outdated nginx + php-fpm target for validating
# php2shell-check.sh and its detections. It handles two possible worlds
# honestly (post-advisory mirrors may no longer serve pre-fix versions):
#
#   vulnerable : installed PHP 8.2.x predates 8.2.35 and no distro backport
#                is present in the changelog  -> checker must say VULN
#   fixed      : mirror only offers >= 8.2.35     -> lab still valid, the
#                verdict matrix adapts (validate.sh reads the recorded truth)
#
# The outcome is recorded in /var/lib/php2shell-lab/{baseline,installed-version}.
# Nothing here exploits anything: this installs REAL packages from distro repos.
#===============================================================================
set -u

LAB_FLAVOR="${LAB_FLAVOR:-debian}"
LAB_PHP="${LAB_PHP:-8.2}"
LAB_DIR="/var/lib/php2shell-lab"
WEBROOT="/var/www/lab"

case "$LAB_PHP" in
  8.2) FIXED="8.2.35" ;; 8.3) FIXED="8.3.36" ;;
  8.4) FIXED="8.4.27" ;; 8.5) FIXED="8.5.12" ;;
  *)   FIXED="8.2.35" ;;
esac

say() { printf '\n[provision] %s\n' "$*"; }
die() { printf '[provision] FATAL: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (vagrant does this for you)"
. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
mkdir -p "$LAB_DIR"
export DEBIAN_FRONTEND=noninteractive

ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }
upstream_of() { php -r 'echo PHP_VERSION;' 2>/dev/null || printf ''; }

#--------------------------------- base packages ------------------------------
say "os=${ID} ${VERSION_ID:-?} | flavor=${LAB_FLAVOR} | php branch ${LAB_PHP} (fix at ${FIXED})"
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg lsb-release nginx auditd rsyslog \
  || die "base package installation failed"
WWW_UID="$(id -u www-data 2>/dev/null || echo 33)"

#--------------------------------- extra repos --------------------------------
setup_extra_repo() { # sury (Debian) / ondrej (Ubuntu) - needed for upgrade drill
  if [ "$ID" = "debian" ]; then
    install -d -m 755 /etc/apt/keyrings
    curl -fsSL https://packages.sury.org/php/apt.gpg -o /etc/apt/keyrings/sury-php.asc
    printf 'deb [signed-by=/etc/apt/keyrings/sury-php.asc] https://packages.sury.org/php %s main\n' \
      "${VERSION_CODENAME:-bookworm}" > /etc/apt/sources.list.d/sury-php.list
  else
    apt-get install -y -qq software-properties-common >/dev/null
    add-apt-repository -y ppa:ondrej/php >/dev/null
  fi
  apt-get update -qq
}

#--------------------------------- install PHP --------------------------------
baseline="fixed"; ver=""
if [ "$LAB_FLAVOR" = "debian" ] && apt-get install -y -qq "php${LAB_PHP}-fpm" "php${LAB_PHP}-cli" >/dev/null 2>&1; then
  ver="$(upstream_of)"
  say "stock Debian php${LAB_PHP} installed: ${ver}"
else
  say "stock ${LAB_PHP} unavailable -> enabling sury/ondrej repo"
  setup_extra_repo
  lowest="$(apt-cache madison "php${LAB_PHP}-fpm" 2>/dev/null | awk '{print $3}' | sort -V | head -n1)"
  if [ -n "$lowest" ] && ver_lt "$lowest" "$FIXED"; then
    say "pinning lowest available pre-fix build: ${lowest}"
    apt-get install -y -qq --allow-downgrades "php${LAB_PHP}-fpm=${lowest}" "php${LAB_PHP}-cli=${lowest}" \
      || apt-get install -y -qq "php${LAB_PHP}-fpm" "php${LAB_PHP}-cli"
  else
    apt-get install -y -qq "php${LAB_PHP}-fpm" "php${LAB_PHP}-cli"
  fi
  ver="$(upstream_of)"
fi
[ -n "$ver" ] || die "php not installed?"

# backport check: same oracle the checker uses (distro changelog cites the CVEs)
if ver_lt "$ver" "$FIXED"; then
  backported=0
  for cl in /usr/share/doc/php${LAB_PHP}-common/changelog.Debian*.gz; do
    [ -e "$cl" ] || continue
    zcat "$cl" 2>/dev/null | grep -qE 'CVE-2026-10961[89]' && backported=1 && break
  done
  [ "$backported" -eq 0 ] && baseline="vulnerable"
  [ "$backported" -eq 1 ] && say "distro changelog already cites the CVEs (backport) -> baseline=fixed"
fi
say "baseline verdict for this VM: ${baseline} (php ${ver})"
printf '%s\n' "$ver"      > "$LAB_DIR/installed-version"
printf '%s\n' "$baseline" > "$LAB_DIR/baseline"

#--------------------------------- lab ini ------------------------------------
# enabled=1 keeps the known attack-path feature ON (that is the exposure the
# checker reports); cleanup=0 keeps progress records in the session file so
# the T3 canary can actually be found by detection queries.
for d in /etc/php/${LAB_PHP}/fpm /etc/php/${LAB_PHP}/cli; do
  [ -d "$d/conf.d" ] || continue
  cat > "$d/conf.d/90-lab.ini" <<'INI'
; php2shell-lab: make the upload-progress path visible and persistent
session.upload_progress.enabled = 1
session.upload_progress.cleanup = 0
INI
done

#--------------------------------- web app (benign) ---------------------------
mkdir -p "$WEBROOT"
cat > "$WEBROOT/index.php" <<'PHP'
<?php
header('Content-Type: text/plain');
printf("php2shell-lab target\nPHP %s (fpm)\n", PHP_VERSION);
printf("session.upload_progress.enabled = %s\n", (string) ini_get('session.upload_progress.enabled'));
printf("session.upload_progress.cleanup = %s\n", (string) ini_get('session.upload_progress.cleanup'));
PHP
cat > "$WEBROOT/upload.php" <<'PHP'
<?php
// Benign receiver: persists nothing to disk. It exists so the
// session-upload-progress code path can be exercised for detection canaries.
session_start();
header('Content-Type: application/json');
$prog = isset($_POST['PHP_SESSION_UPLOAD_PROGRESS']) ? $_POST['PHP_SESSION_UPLOAD_PROGRESS'] : '(none)';
echo json_encode(['progress_key' => $prog, 'files' => array_keys($_FILES)]);
PHP
chown -R www-data:www-data "$WEBROOT"

#--------------------------------- nginx site ---------------------------------
cat > /etc/nginx/sites-available/php2shell-lab <<NGINX
server {
    listen 8080 default_server;
    server_name _;
    root ${WEBROOT};
    index index.php;
    access_log /var/log/nginx/lab-access.log;
    location / { try_files \$uri \$uri/ /index.php?\$query_string; }
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${LAB_PHP}-fpm.sock;
    }
}
NGINX
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/php2shell-lab /etc/nginx/sites-enabled/php2shell-lab

#--------------------------------- auditd rules -------------------------------
mkdir -p /var/lib/php/sessions
cat > /etc/audit/rules.d/php2shell-lab.rules <<RULES
-w ${WEBROOT}/ -p wa -k lab_webroot
-w /var/lib/php/sessions/ -p wa -k lab_sessions
-a always,exit -F arch=b64 -S execve -F euid=${WWW_UID} -k lab_www_exec
-a always,exit -F arch=b32 -S execve -F euid=${WWW_UID} -k lab_www_exec
RULES
systemctl enable --now auditd rsyslog >/dev/null 2>&1 || true
augenrules --load >/dev/null 2>&1 || systemctl restart auditd

#--------------------------------- services -----------------------------------
systemctl restart "php${LAB_PHP}-fpm" nginx
systemctl is-active --quiet "php${LAB_PHP}-fpm" || die "php-fpm did not start"
systemctl is-active --quiet nginx           || die "nginx did not start"
nginx -t 2>/dev/null || true
curl -fsS http://127.0.0.1:8080/index.php >/dev/null || die "local http check failed"

printf '%s\n' "php2shell-lab ready" > "$LAB_DIR/README"
chmod 644 "$LAB_DIR"/*

cat <<EOF

[provision] ============================================================
[provision] lab target ready
[provision]   php          : ${ver}   (baseline: ${baseline}, fix at ${FIXED})
[provision]   web          : http://$(hostname -I 2>/dev/null | awk '{print $1}'):8080/  (also via http://127.0.0.1:8080 inside the VM)
[provision]   auditd rules : lab_webroot / lab_sessions / lab_www_exec
[provision] next steps (from the kit directory on the HOST):
[provision]   vagrant ssh -c 'sudo bash /vagrant/validate.sh baseline'
[provision]   vagrant ssh -c 'sudo bash /vagrant/simulate-ttps.sh'
[provision] ============================================================
EOF
