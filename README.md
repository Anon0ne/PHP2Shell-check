# php2shell-lab — purple-team patch-verification rig (CVE-2026-109618 / 109619)

Disposable Debian 12 / Ubuntu 22.04 target that proves two things end to end:

1. **php2shell-check.sh verdicts are right** — pre-fix build -> VULN (exit 1),
   upgraded-and-restarted -> OK (exit 0), and the "upgraded but NOT restarted"
   gap is caught through /proc.
2. **Your detection actually fires** — auditd rules + log/session queries are
   armed, then benign TTP canaries (canary webshell, www-data shell spawns,
   upload-progress on-ramp traffic) prove each one works.

No exploit code exists anywhere in this kit — every red-side action is a
labeled, harmless canary.

## Quickstart (host side)

    cd php2shell-lab
    vagrant up                                  # Debian 12 flavor
    # second VM on the same LAN (Ubuntu flavor):
    LAB_FLAVOR=ubuntu LAB_IP=192.168.56.11 vagrant up

## Exercise (inside the VM, via vagrant ssh)

    vagrant ssh -c 'sudo bash /vagrant/validate.sh baseline'          # 1 scanner truth
    vagrant ssh -c 'sudo bash /vagrant/simulate-ttps.sh'              # 2 fire canaries
    vagrant ssh -c 'sudo bash /vagrant/validate.sh ttps'              # 3 prove detection
    vagrant ssh -c 'sudo bash /vagrant/upgrade-to-fixed.sh'           # 4 patch, NO restart
    vagrant ssh -c 'sudo bash /vagrant/validate.sh upgraded-unrestarted'  # 5 gap caught
    vagrant ssh -c 'sudo systemctl restart php8.2-fpm'                # 6 load the patch
    vagrant ssh -c 'sudo bash /vagrant/validate.sh fixed'             # 7 ALL CLEAR

## Fleet mode (host side) — same flow you will run on real hardware

    ./make-servers-txt.sh
    bash php2shell-check.sh --servers servers.txt

Full procedure, pass/fail criteria and troubleshooting: `php2shell-lab-runbook.docx`.

Teardown: `./teardown.sh`
