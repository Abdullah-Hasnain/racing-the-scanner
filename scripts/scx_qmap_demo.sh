#!/usr/bin/env bash
# Milestone 3 demo (#11): per-PID weights on a real kernel, mirroring the sim.
#
# kernel/scx_qmap_pidweight.patch makes scx_qmap scale each task's time slice by
# a weight read from the pinned BPF map /sys/fs/bpf/pid_weight (100 = default).
# As in the sim (sim/policies/base.py), weight sets CPU share. Two CPU-bound
# workers, "victim" and "attacker", are pinned to CPU 0, and each one's CPU% is
# sampled from /proc/<pid>/stat (utime+stime deltas) in three phases:
#   baseline  no override            -> about even
#   attack    attacker weight 2000   -> attacker dominates, victim starves
#   penalty   attacker weight 10     -> victim recovers (the sim's 0.1x penalty)
#
#   sudo bash scripts/scx_qmap_demo.sh 2>&1 | tee /tmp/scx_qmap_demo.out
#
# Needs a sched_ext kernel (docs/kernel-spike.md) and 2+ CPUs. Env overrides:
# KTREE (Linux tree; fetched as in kernel_spike.sh if missing), WINDOW (seconds
# per sample, 3), WINDOWS (samples per phase, 3), ATTACK_WEIGHT (2000),
# PENALTY_WEIGHT (10).
set -u
say() { printf '\n== %s ==\n' "$*"; }
here=$(cd "$(dirname "$0")" && pwd)
PATCH="$here/../kernel/scx_qmap_pidweight.patch"
SETW="$here/scx_pid_weight.sh"
SE=/sys/kernel/sched_ext
PIN=/sys/fs/bpf/pid_weight
WINDOW=${WINDOW:-3}
WINDOWS=${WINDOWS:-3}
ATTACK_WEIGHT=${ATTACK_WEIGHT:-2000}
PENALTY_WEIGHT=${PENALTY_WEIGHT:-10}
HZ=$(getconf CLK_TCK)
QPID='' VPID='' APID=''
export DEBIAN_FRONTEND=noninteractive

[ "$(id -u)" = 0 ] || { echo "run as root: sudo bash $0"; exit 1; }
[ -d "$SE" ] || { echo "no sched_ext in this kernel; see docs/kernel-spike.md"; exit 1; }
[ "$(nproc)" -ge 2 ] || { echo "need 2+ CPUs: CPU 0 for the workers, another for this script"; exit 1; }

say "box"
echo "kernel: $(uname -r)"
. /etc/os-release && echo "distro: $PRETTY_NAME"
echo "virt: $(systemd-detect-virt 2>/dev/null || true)  nproc: $(nproc)"

say "build the patched scx_qmap"
systemctl disable --now scx.service >/dev/null 2>&1 || true
if [ "$(cat "$SE/state")" != disabled ]; then
  echo "FAIL: another sched_ext scheduler is loaded ($(cat "$SE/root/ops")); stop it first"
  exit 1
fi
apt-get install -y -qq git clang llvm gcc make libelf-dev zlib1g-dev pkg-config libssl-dev >/dev/null
tag=v$(uname -r | cut -d. -f1,2)
KTREE=${KTREE:-/var/tmp/kernel-spike/linux-$tag}
if [ ! -d "$KTREE/tools/sched_ext" ]; then
  echo "fetching the kernel tree $tag into $KTREE"
  mkdir -p "$(dirname "$KTREE")"
  git clone -q --depth 1 --branch "$tag" --filter=blob:none --sparse \
    https://github.com/torvalds/linux.git "$KTREE" 2>/dev/null \
    && git -C "$KTREE" sparse-checkout set tools kernel/bpf include scripts \
    || { echo "FAIL: could not fetch kernel tree $tag (set KTREE)"; exit 1; }
fi
if git -C "$KTREE" apply --reverse --check "$PATCH" 2>/dev/null; then
  echo "patch: already applied in $KTREE"
elif git -C "$KTREE" apply "$PATCH"; then
  echo "patch: applied to $KTREE"
else
  echo "FAIL: $PATCH does not apply to $KTREE"
  exit 1
fi
if ! make -C "$KTREE/tools/sched_ext" -j"$(nproc)" scx_qmap >/tmp/scx_qmap_make.log 2>&1; then
  echo "FAIL: build failed; errors from /tmp/scx_qmap_make.log:"
  grep -E 'error|Error' /tmp/scx_qmap_make.log | head -n 20
  exit 1
fi
QMAP=$KTREE/tools/sched_ext/build/bin/scx_qmap
echo "built: $QMAP"
# the sched_ext build also produces a bpftool; use it if the system has none
command -v bpftool >/dev/null || export PATH="$KTREE/tools/sched_ext/build/sbin:$PATH"
echo "bpftool: $(command -v bpftool)"

say "load scx_qmap"
cleanup() {
  [ -n "$VPID" ] && kill "$VPID" 2>/dev/null
  [ -n "$APID" ] && kill "$APID" 2>/dev/null
  if [ -n "$QPID" ]; then kill -INT "$QPID" 2>/dev/null; wait "$QPID" 2>/dev/null; fi
  VPID='' APID='' QPID=''
  rm -f "$PIN" "${RES:-}"
}
trap cleanup EXIT
taskset -cp 1 $$ >/dev/null   # keep this script and scx_qmap off CPU 0
rm -f "$PIN"
"$QMAP" >/tmp/scx_qmap.log 2>&1 &
QPID=$!
for _ in $(seq 1 40); do
  [ "$(cat "$SE/state")" = enabled ] && [ -e "$PIN" ] && break
  sleep 0.25
done
ops=$(cat "$SE/root/ops" 2>/dev/null)
echo "state: $(cat "$SE/state")  root/ops: $ops  map: $(ls "$PIN" 2>/dev/null || echo missing)"
if [ "$ops" != qmap ] || [ ! -e "$PIN" ]; then
  echo "FAIL: scx_qmap did not come up"; cat /tmp/scx_qmap.log; exit 1
fi

say "start victim and attacker, both pinned to CPU 0"
taskset -c 0 bash -c 'echo -n victim > /proc/self/comm; while :; do :; done' &
VPID=$!
taskset -c 0 bash -c 'echo -n attacker > /proc/self/comm; while :; do :; done' &
APID=$!
sleep 0.5
for p in "$VPID" "$APID"; do
  echo "pid $p: comm=$(cat "/proc/$p/comm") cpus=$(taskset -cp "$p" | sed 's/.*: //')" \
       "$(grep -E '^ext\.enabled' "/proc/$p/sched" | tr -s ' ')"
done

ticks() {  # utime+stime of a pid, in clock ticks (fields 14 and 15 of stat)
  local s
  s=$(cat "/proc/$1/stat") || return 1
  s=${s##*) }   # drop "pid (comm) " so the fields below are stat 3..
  set -- $s
  echo $(( ${12} + ${13} ))
}
sample() {  # "victim% attacker%" over one WINDOW
  local v0 a0 t0 v1 a1 t1
  v0=$(ticks "$VPID"); a0=$(ticks "$APID"); t0=$(date +%s%N)
  sleep "$WINDOW"
  v1=$(ticks "$VPID"); a1=$(ticks "$APID"); t1=$(date +%s%N)
  awk -v dv=$((v1 - v0)) -v da=$((a1 - a0)) -v dt=$((t1 - t0)) -v hz="$HZ" \
    'BEGIN { s = dt / 1e9; printf "%.1f %.1f\n", 100 * dv / hz / s, 100 * da / hz / s }'
}
RES=$(mktemp)
phase() {  # name, attacker weight (100 = no override)
  local name=$1 w=$2 i out
  if [ "$w" = 100 ]; then bash "$SETW" "$APID" clear; else bash "$SETW" "$APID" "$w"; fi ||
    { echo "FAIL: could not set the attacker's weight to $w"; exit 1; }
  say "phase $name: attacker weight $w$([ "$w" = 100 ] && echo ' (no override)')"
  echo "map: $(bash "$SETW" show | tr -s ' \n' ' ')"
  sleep 1   # a new weight takes effect at the attacker's next slice
  for i in $(seq 1 "$WINDOWS"); do
    out=$(sample)
    printf '  window %d (%ss): victim %5s%%  attacker %5s%%\n' "$i" "$WINDOW" "${out% *}" "${out#* }"
    echo "$name $w $out" >>"$RES"
  done
}

phase baseline 100
phase attack "$ATTACK_WEIGHT"
phase penalty "$PENALTY_WEIGHT"

say "scx_qmap while running"
echo "root/ops: $(cat "$SE/root/ops")"
grep '^stats' /tmp/scx_qmap.log | tail -n 1
cleanup
trap - EXIT
tail -n 1 /tmp/scx_qmap.log
echo "state after: $(cat "$SE/state")  map after: $(ls "$PIN" 2>/dev/null || echo removed)"

say "result (mean of $WINDOWS x ${WINDOW}s windows per phase)"
# model: victim slice 20ms (SCX_SLICE_DFL), attacker slice 20ms * w / 100 clamped
# to [0.2, 1000] ms, so the victim gets 20 / (20 + s_a): the sim's w_v / (w_v + w_a)
echo "| phase | attacker weight | victim CPU% | attacker CPU% | victim model % |"
echo "|---|---|---|---|---|"
awk '
  !($1 in n) { order[++k] = $1 }
  { n[$1]++; w[$1] = $2; v[$1] += $3; a[$1] += $4 }
  END {
    for (i = 1; i <= k; i++) {
      p = order[i]; sa = 20 * w[p] / 100
      if (sa < 0.2) sa = 0.2
      if (sa > 1000) sa = 1000
      printf "| %s | %s | %.1f | %.1f | %.1f |\n", p, w[p], v[p] / n[p], a[p] / n[p], 100 * 20 / (20 + sa)
    }
  }' "$RES"
read -r vb va vp < <(awk '{ n[$1]++; v[$1] += $3 }
  END { printf "%.1f %.1f %.1f\n", v["baseline"] / n["baseline"], v["attack"] / n["attack"], v["penalty"] / n["penalty"] }' "$RES")
rm -f "$RES"
echo
if awk -v b="$vb" -v x="$va" -v p="$vp" 'BEGIN { exit !(x < b / 2 && p > 2 * x) }'; then
  echo "PASS: the victim's CPU dropped under the attack (${vb}% -> ${va}%) and recovered under the penalty (${vp}%)."
else
  echo "UNCLEAR: victim ${vb}% -> ${va}% -> ${vp}%; see the per-window samples above."
  exit 1
fi
