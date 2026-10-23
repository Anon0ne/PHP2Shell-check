#!/usr/bin/env bash
#===============================================================================
# make-servers-txt.sh — host-side helper (run from the kit dir AFTER `vagrant up`).
#
# Generates servers.txt from the running Vagrant machines so the checker's SSH
# fleet mode can scan the lab exactly like production. The same file format is
# what you will use against the real Debian/Ubuntu boxes on your closed LAN:
#
#   ops@web-01
#   ops@192.168.10.20 -p 2222
#   vagrant@127.0.0.1 -p 2222 -i /abs/path/key -o IdentitiesOnly=yes
#
# Then:   bash php2shell-check.sh --servers servers.txt
#===============================================================================
set -u

out="${1:-servers.txt}"
[ -d .vagrant ] || { echo "no .vagrant dir here - run 'vagrant up' first"; exit 1; }

: > "$out"
found=0
for key in .vagrant/machines/*/virtualbox/private_key; do
  [ -f "$key" ] || continue
  name="$(printf '%s' "$key" | cut -d/ -f3)"
  cfg="$(vagrant ssh-config "$name" 2>/dev/null || vagrant ssh-config)"
  [ -n "$cfg" ] || continue
  host="$(awk '/HostName/{print $2; exit}' <<<"$cfg")"
  user="$(awk '/^ *User /{print $2; exit}'  <<<"$cfg")"
  port="$(awk '/^ *Port /{print $2; exit}'  <<<"$cfg")"
  idf="$(awk '/IdentityFile/{print $2; exit}' <<<"$cfg")"
  [ -n "$host" ] && [ -n "$user" ] || continue
  printf '%s@%s -p %s -i %s -o IdentitiesOnly=yes\n' "$user" "$host" "${port:-22}" "${idf:-$key}" >> "$out"
  found=$((found+1))
done

[ "$found" -gt 0 ] || { echo "no running machines found"; exit 1; }
echo "-- wrote ${out} (${found} target(s)) --"
cat "$out"
printf '\nnow scan the lab fleet from the host:\n  bash php2shell-check.sh --servers %s\n' "$out"
