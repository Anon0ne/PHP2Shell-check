# -*- ruby -*-
#===============================================================================
# php2shell-lab Vagrantfile — purple-team lab for CVE-2026-109618/109619
#
# Brings up a disposable Debian 12 (or Ubuntu 22.04) target with an outdated
# nginx + php-fpm stack, auditd detection rules and a benign upload app, then
# runs provision.sh inside. The kit scripts are available in the VM at /vagrant.
#
# Usage (from this directory):
#   vagrant up                        # Debian 12 flavor
#   LAB_FLAVOR=ubuntu LAB_IP=192.168.56.11 vagrant up   # Ubuntu flavor, 2nd VM
#   vagrant provision                 # re-run bootstrap
#   vagrant destroy -f                # teardown (or ./teardown.sh)
#
# flavor knobs:
#   LAB_FLAVOR  debian (default) | ubuntu
#   LAB_IP      private-LAN address, default 192.168.56.10
#   LAB_PHP     vulnerable branch to install, default 8.2
#===============================================================================
VAGRANTFILE_API_VERSION = "2"

LAB_FLAVOR = ENV.fetch("LAB_FLAVOR", "debian")
LAB_IP     = ENV.fetch("LAB_IP", "192.168.56.10")
LAB_PHP    = ENV.fetch("LAB_PHP", "8.2")

IS_UBUNTU = LAB_FLAVOR == "ubuntu"
BOX       = IS_UBUNTU ? "bento/ubuntu-22.04" : "bento/debian-12"
NAME      = IS_UBUNTU ? "php2shell-lab-ubuntu" : "php2shell-lab-debian"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box    = BOX
  config.vm.hostname = NAME
  config.vm.network "private_network", ip: LAB_IP
  config.vm.synced_folder ".", "/vagrant"

  config.vm.provision "shell", path: "provision.sh", env: {
    "LAB_FLAVOR" => LAB_FLAVOR,
    "LAB_PHP"    => LAB_PHP,
  }

  config.vm.provider "virtualbox" do |vb|
    vb.name   = NAME
    vb.memory = 1024
    vb.cpus   = 1
  end
end
