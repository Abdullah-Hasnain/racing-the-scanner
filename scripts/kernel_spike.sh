#!/usr/bin/env bash
# Milestone 3 spike (#10): confirm a sched_ext (scx) scheduler loads on a real
# Linux 6.12+ kernel. Run as root on an x86-64 Ubuntu VM (a real VM, not a
# container). Read-only until the apt installs, the scx_simple build, and the
# brief scx_simple load, which reverts to the stock scheduler when it exits.
#
#   git clone <repo> && cd racing-the-scanner
#   sudo bash scripts/kernel_spike.sh 2>&1 | tee /tmp/kernel_spike.out
#
# Copy the output into docs/kernel-spike.md. A kernel without sched_ext is a
# valid outcome: document it; the simulation remains the deliverable.
#
# Env overrides: SCX_SIMPLE=/path/to/scx_simple (skip the build),
# KERNEL_TAG=vX.Y (kernel tree to build from), SPIKE_DIR (work dir).
set -u
say() { printf '\n== %s ==\n' "$*"; }
SE=/sys/kernel/sched_ext
[ "$(id -u)" = 0 ] || { echo "run as root: sudo bash $0"; exit 1; }
export DEBIAN_FRONTEND=noninteractive

say "box"
uname -a
. /etc/os-release 2>/dev/null && echo "distro: ${PRETTY_NAME:-unknown}"
echo "virt: $(systemd-detect-virt 2>/dev/null || true)  nproc: $(nproc)"

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
[ -d "$SE" ] && { echo "$SE: present"; ext_ok=1; } || echo "$SE: missing"

if [ "$ext_ok" = 0 ]; then
  cat <<'EOF'

RESULT: this kernel has no sched_ext. Valid #10 outcome; record it and stop.
Fix: use an Ubuntu 26.04 (resolute) x86-64 image (its generic kernel ships sched_ext),
or on 24.04 add the PPA kernel and reboot (untested here):
  sudo add-apt-repository -y --enable-source ppa:arighi/sched-ext
  sudo apt install -y linux-generic-wip scx && sudo reboot
EOF
  exit 1
fi

say "install scx tools"
apt-get update -qq
# scx is not in the Ubuntu archive; it comes from ppa:arighi/sched-ext.
if ! apt-cache policy scx 2>/dev/null | grep -q 'Candidate: [0-9]'; then
  apt-get install -y -qq software-properties-common >/dev/null
  add-apt-repository -y ppa:arighi/sched-ext >/dev/null
  apt-get update -qq
fi
if ! apt-get install -y -qq scx >/dev/null; then
  echo "FAIL: apt could not install scx (check that ppa:arighi/sched-ext builds for this release)."
  exit 1
fi
apt-cache policy scx | sed -n '1,3p'
# The package enables scx.service, which loads scx_cosmos immediately. Stop it
# so the test starts from the stock scheduler and measures scx_simple alone.
systemctl disable --now scx.service >/dev/null 2>&1 || true
echo "scx.service: $(systemctl is-active scx.service 2>/dev/null)"

say "locate or build scx_simple"
# The scx package ships only the Rust schedulers; upstream scx dropped its C
# examples, so scx_simple is built from the kernel tree (tools/sched_ext).
SCX_SIMPLE=${SCX_SIMPLE:-$(command -v scx_simple || true)}
if [ -z "$SCX_SIMPLE" ]; then
  dir=${SPIKE_DIR:-/var/tmp/kernel-spike}
  tag=${KERNEL_TAG:-v$(uname -r | cut -d. -f1,2)}
  src="$dir/linux-$tag"
  echo "building from the kernel tree at $tag in $dir"
  # libssl-dev: the bootstrap bpftool needs OpenSSL headers (sign.c, 7.0+).
  apt-get install -y -qq git clang llvm gcc make libelf-dev zlib1g-dev pkg-config libssl-dev >/dev/null
  mkdir -p "$dir"
  if [ ! -d "$src" ]; then
    git clone -q --depth 1 --branch "$tag" --filter=blob:none --sparse \
      https://github.com/torvalds/linux.git "$src" 2>/dev/null \
      && git -C "$src" sparse-checkout set tools kernel/bpf include scripts \
      || { echo "FAIL: could not fetch kernel tree $tag (set KERNEL_TAG)"; exit 1; }
  fi
  if ! make -C "$src/tools/sched_ext" -j"$(nproc)" scx_simple >"$dir/make.log" 2>&1; then
    echo "FAIL: scx_simple build failed; errors from $dir/make.log:"
    grep -E 'error|Error' "$dir/make.log" | head -n 20
    exit 1
  fi
  SCX_SIMPLE="$src/tools/sched_ext/build/bin/scx_simple"
  echo "clang: $(clang --version | head -n 1)"
fi
echo "scx_simple: $SCX_SIMPLE"

say "before load"
state0=$(cat "$SE/state" 2>/dev/null); seq0=$(cat "$SE/enable_seq" 2>/dev/null || echo 0)
echo "state:      $state0"
echo "enable_seq: $seq0"

say "load scx_simple for ~8s"
timeout 8 "$SCX_SIMPLE" >/tmp/scx_simple.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null' EXIT   # a Ctrl-C here must not leave scx_simple loaded
sleep 3
say "confirm it is live (while running)"
state1=$(cat "$SE/state" 2>/dev/null); ops1=$(cat "$SE/root/ops" 2>/dev/null)
seq1=$(cat "$SE/enable_seq" 2>/dev/null || echo 0)
grep ext /proc/self/sched 2>/dev/null | grep -i 'ext.enabled' || echo "ext.enabled: (not on this task)"
echo "state:      $state1"
echo "root/ops:   $ops1"
echo "enable_seq: $seq1"
echo "switch_all: $(cat "$SE/switch_all" 2>/dev/null)"
echo "tasks by ext.enabled (from /proc/*/sched):"
grep -h '^ext\.enabled' /proc/[0-9]*/sched 2>/dev/null | awk '{print "  ext.enabled=" $NF}' | sort | uniq -c
wait "$pid"; rc=$?
trap - EXIT
echo "scx_simple exit code: $rc (124 = stopped by the timeout, expected)"
say "scx_simple stdout"
cat /tmp/scx_simple.log

say "after unload"
echo "state:      $(cat "$SE/state" 2>/dev/null)"
dmesg 2>/dev/null | grep 'sched_ext: BPF scheduler' | tail -n 2

say "RESULT"
# enable_seq is cumulative (the package's own scheduler bumps it too), so PASS
# needs scx_simple itself live: state enabled, ops simple, seq incremented.
if [ "$state1" = enabled ] && [ "$ops1" = simple ] && [ "$seq1" -gt "$seq0" ]; then
  echo "PASS: scx_simple loaded (state enabled, root/ops simple, enable_seq $seq0 -> $seq1). Proceed to #11."
else
  echo "FAIL: scx_simple was not the live scheduler (state=$state1 ops=$ops1 enable_seq $seq0 -> $seq1). See /tmp/scx_simple.log above."
  exit 1
fi
