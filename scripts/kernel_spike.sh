#!/usr/bin/env bash
# Milestone 3 spike (#10): confirm a sched_ext (scx) scheduler loads on a real
# Linux 6.12+ kernel. Run on an x86-64 cloud VM (a real VM, not a container) as a
# user with sudo. Read-only until the apt install and the brief scx_simple load,
# which reverts to the stock scheduler as soon as the script stops it.
#
#   git clone <repo> && cd racing-the-scanner
#   sudo bash scripts/kernel_spike.sh 2>&1 | tee /tmp/kernel_spike.out
#
# Copy the output into docs/kernel-spike.md. A kernel without sched_ext is a
# valid outcome: document it; the simulation remains the deliverable.
set -u
say() { printf '\n== %s ==\n' "$*"; }

say "box"
uname -a
. /etc/os-release 2>/dev/null && echo "distro: ${PRETTY_NAME:-unknown}"

say "kernel sched_ext support"
cfg="/boot/config-$(uname -r)"
if [ -r "$cfg" ]; then
  grep -E 'CONFIG_SCHED_CLASS_EXT|CONFIG_DEBUG_INFO_BTF|CONFIG_BPF_SYSCALL' "$cfg" || true
elif zcat /proc/config.gz 2>/dev/null | grep -q CONFIG_SCHED_CLASS_EXT; then
  zcat /proc/config.gz | grep -E 'CONFIG_SCHED_CLASS_EXT|CONFIG_DEBUG_INFO_BTF|CONFIG_BPF_SYSCALL'
else
  echo "(kernel config not readable; relying on sysfs)"
fi
ext_ok=0
grep -q 'CONFIG_SCHED_CLASS_EXT=y' "$cfg" 2>/dev/null && ext_ok=1
[ -d /sys/kernel/sched_ext ] && { echo "/sys/kernel/sched_ext: present"; ext_ok=1; } || echo "/sys/kernel/sched_ext: missing"

if [ "$ext_ok" = 0 ]; then
  cat <<'EOF'

RESULT: this kernel has no sched_ext. Valid #10 outcome; record it and stop.
Fix: use an Ubuntu 25.04 (plucky) x86-64 image (its generic kernel ships sched_ext),
or on 24.04 add the PPA kernel and reboot:
  sudo add-apt-repository -y --enable-source ppa:arighi/sched-ext
  sudo apt install -y linux-generic-wip scx && sudo reboot
EOF
  exit 1
fi

say "install scx tools"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
if ! sudo apt-get install -y scx; then
  cat <<'EOF'
'scx' not in the archive here. Add the PPA, then re-run this script:
  sudo add-apt-repository -y --enable-source ppa:arighi/sched-ext
  sudo apt update && sudo apt install -y scx
EOF
  exit 1
fi
if ! command -v scx_simple >/dev/null; then
  echo "scx_simple not found. Available scx binaries:"
  ls /usr/bin/scx_* 2>/dev/null || echo "(none)"
  echo "Pick one above and substitute it for scx_simple below."
  exit 1
fi

say "load scx_simple for ~8s"
sudo timeout 8 scx_simple >/tmp/scx_simple.log 2>&1 &
sleep 3
say "confirm it is live (while running)"
grep ext /proc/self/sched 2>/dev/null | grep -i 'ext.enabled' || echo "ext.enabled: (not on this task)"
echo "state:      $(cat /sys/kernel/sched_ext/state 2>/dev/null)"
echo "root/ops:   $(cat /sys/kernel/sched_ext/root/ops 2>/dev/null)"
echo "enable_seq: $(cat /sys/kernel/sched_ext/enable_seq 2>/dev/null)"
wait
say "scx_simple stdout"
cat /tmp/scx_simple.log

say "RESULT"
if [ "$(cat /sys/kernel/sched_ext/enable_seq 2>/dev/null || echo 0)" != "0" ]; then
  echo "PASS: scx_simple loaded (enable_seq > 0). sched_ext works on this box; proceed to #11."
else
  echo "FAIL: enable_seq is 0; scx_simple did not load. See /tmp/scx_simple.log above."
fi
