#!/usr/bin/env bash
# Set a per-PID weight for the patched scx_qmap (#11, kernel/scx_qmap_pidweight.patch).
#
#   sudo scripts/scx_pid_weight.sh PID WEIGHT   # 100 = default, 1000 = 10x the slice
#   sudo scripts/scx_pid_weight.sh PID clear    # back to stock scx_qmap behavior
#   sudo scripts/scx_pid_weight.sh show         # dump the map
#
# The map is pinned at /sys/fs/bpf/pid_weight while scx_qmap runs. Its key is a
# pid_t and its value a u32, both 4-byte little-endian. bpftool takes raw bytes,
# so this script does the encoding.
set -eu
MAP=${PID_WEIGHT_MAP:-/sys/fs/bpf/pid_weight}

usage() { echo "usage: $0 PID WEIGHT | PID clear | show" >&2; exit 2; }
le32() { printf '%d %d %d %d' $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)); }

[ -e "$MAP" ] || { echo "no map at $MAP: is the patched scx_qmap running?" >&2; exit 1; }
case "${1:-}" in
  show) exec bpftool map dump pinned "$MAP" ;;
  '' | *[!0-9]*) usage ;;
esac
pid=$((10#$1))   # 10#: no octal surprises from leading zeros

case "${2:-}" in
  clear) bpftool map delete pinned "$MAP" key $(le32 "$pid") 2>/dev/null || true ;;
  '' | *[!0-9]*) usage ;;
  *)
    w=$((10#$2))
    [ "$w" -ge 1 ] && [ "$w" -le 4294967295 ] || { echo "WEIGHT must be 1..4294967295" >&2; exit 2; }
    bpftool map update pinned "$MAP" key $(le32 "$pid") value $(le32 "$w") any
    ;;
esac
