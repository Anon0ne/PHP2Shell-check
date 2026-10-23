#!/usr/bin/env bash
# teardown.sh — host-side lab teardown (run from the kit directory).
# Destroys the VM(s); boxes stay cached, so a later `vagrant up` is fast.
set -u
vagrant destroy -f "$@"
echo "lab destroyed. to free the cached box later: vagrant box remove <name>"
