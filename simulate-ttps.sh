#!/usr/bin/env bash
#===============================================================================
# simulate-ttps.sh — php2shell-lab TTP emulation (run INSIDE the VM with sudo).
#
# Emulates the observable fingerprints of a php2shell compromise WITHOUT any
# exploit code. Each canary is benign on its own; the value is proving that
# your detection (auditd rules + log/session queries) actually fires.
#
#   T1  canary .php written into the webroot as www-data
#       -> emulates "attacker dropped a webshell"   (MITRE T1505.003)
#          detection: auditd key lab_webroot + file listing
#   T2  /bin/sh, php and curl executed as euid www-data (loopback only)
#       -> emulates "compromised worker spawned tools" (MITRE T1059.004)
#          detection: auditd key lab_www_exec
#   T3  multipart POST carrying PHP_SESSION_UPLOAD_PROGRESS + canary filename
#       -> emulates the recon/primitive the known attack path starts with
#          detection: nginx lab-access.log + /var/lib/php/sessions + lab_sessions
#
# The canary token is stored in /var/lib/php2shell-lab/last-token.
#===============================================================================
set -u

LAB_DIR="/var/lib/php2shell-lab"
WEBROOT="/var/www/lab"
NGX_LOG="/var/log/nginx/lab-access.log"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo bash /vagrant/simulate-ttps.sh"; exit 1; }
[ -f "$LAB_DIR/baseline" ] || { echo "lab not provisioned yet"; exit 1; }

TOKEN="php2shell-lab-$(date +%Y%m%d-%H%M%S)"
echo "$TOKEN" > "$LAB_DIR/last-token"

say() { printf '\n[ttp] %s\n' "$*"; }

#--------------------------------- T1: canary webshell ------------------------
say "T1: dropping BENIGN canary webshell as www-data (${WEBROOT}/canary-${TOKEN}.php)"
sudo -u www-data tee "${WEBROOT}/canary-${TOKEN}.php" >/dev/null <<'PHP'
<?php
/* php2shell-lab canary - benign, intentionally contains NO exec/eval/system.
   Emulates the "new .php in webroot" artifact so your file auditing is proven. */
echo 'php2shell-lab webshell canary - benign';
PHP
say "T1 done -> detect via: sudo ausearch -k lab_webroot -ts today | grep canary"

#--------------------------------- T2: worker spawns tools --------------------
say "T2: /bin/sh, php and curl executed as www-data (loopback only, no egress)"
sudo -u www-data /bin/sh -c 'id'        >/dev/null 2>&1
sudo -u www-data /usr/bin/php -v        >/dev/null 2>&1 || true
sudo -u www-data /usr/bin/curl -fsS -o /dev/null http://127.0.0.1:8080/index.php \
  || say "T2 note: loopback curl failed (nginx up?)"
say "T2 done -> detect via: sudo ausearch -k lab_www_exec -ts today"

#--------------------------------- T3: upload-progress on-ramp canary ---------
say "T3: multipart POST with PHP_SESSION_UPLOAD_PROGRESS + canary filename"
printf 'canary payload %s\n' "$TOKEN" > /tmp/canary-body.txt
curl -fsS -o /dev/null \
  -F "PHP_SESSION_UPLOAD_PROGRESS=${TOKEN}" \
  -F "file=@/tmp/canary-body.txt; filename=canary-${TOKEN}.txt" \
  "http://127.0.0.1:8080/upload.php?key=${TOKEN}" \
  || say "T3 note: POST failed (fpm/nginx up?)"
rm -f /tmp/canary-body.txt
say "T3 done -> detect via: grep '${TOKEN}' ${NGX_LOG}  and  grep -rl '${TOKEN}' /var/lib/php/sessions/"

cat <<EOF

[ttp] ============================================================
[ttp] canary token : ${TOKEN}
[ttp] prove detection:
[ttp]   sudo bash /vagrant/detection-queries.sh --check "${TOKEN}"
[ttp]   (or all phases at once: sudo bash /vagrant/validate.sh ttps)
[ttp] ============================================================
EOF
