#!/usr/bin/env bash
#===============================================================================
# upgrade-to-fixed.sh — php2shell-lab mitigation drill (run with sudo).
#
# Upgrades PHP to >= the fixed release (8.2.35) but INTENTIONALLY does NOT
# restart php-fpm. That reproduces the single most dangerous operational gap:
#   "we installed the patch" != "we are running the patch"
# The still-running workers keep executing the OLD binary (shows as
# "(deleted)" in /proc/<pid>/exe) and php2shell-check.sh must catch it.
#
# After this script:
#   1) sudo bash /vagrant/validate.sh upgraded-unrestarted   -> expect FAIL=VULN (rc 1)
#   2) sudo systemctl restart php8.2-fpm                     -> load the patch
#   3) sudo bash /vagrant/validate.sh fixed                  -> expect ALL CLEAR (rc 0)
#===============================================================================
set -u

LAB_PHP="${LAB_PHP:-8.2}"
LAB_DIR="/var/lib/php2shell-lab"
case "$LAB_PHP" in
  8.2) FIXED="8.2.35" ;; 8.3) FIXED="8.3.36" ;;
  8.4) FIXED="8.4.27" ;; 8.5) FIXED="8.5.12" ;;
  *)   FIXED="8.2.35" ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo bash /vagrant/upgrade-to-fixed.sh"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release 2>/dev/null

# enable sury/ondrej so the post-advisory build is reachable
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

before="$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo none)"
apt-get install -y -qq "php${LAB_PHP}-fpm" "php${LAB_PHP}-cli" || { echo "upgrade failed"; exit 1; }
after="$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo none)"
printf '%s\n' "$after" > "$LAB_DIR/upgraded-version"

if [ "$before" = "$after" ]; then
  echo "nothing to upgrade (${before} already installed) - drill degrades to a restart check"
  touch "$LAB_DIR/drill-noop"
  echo "restart fpm, then validate: sudo bash /vagrant/validate.sh fixed"
  exit 0
fi

cat <<EOF

[drill] upgraded php ${before} -> ${after} WITHOUT restarting php-fpm (intentional)
[drill] the running workers still execute the OLD (pre-patch) binary
[drill] now prove the checker catches the gap:
[drill]   1) sudo bash /vagrant/validate.sh upgraded-unrestarted    # expect VULN via /proc
[drill]   2) sudo systemctl restart php${LAB_PHP}-fpm                   # load the patched binary
[drill]   3) sudo bash /vagrant/validate.sh fixed                   # expect exit 0
EOF
