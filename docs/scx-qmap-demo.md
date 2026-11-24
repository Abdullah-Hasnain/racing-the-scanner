# scx_qmap per-PID weight demo (M3, #11)

**Result: PASS** (2026-11-25). On a real kernel (Linux 7.0, sched_ext), a
patched `scx_qmap` reads a per-PID weight from a pinned BPF map and scales that
task's time slice by it. Two CPU-bound workers pinned to one CPU split it
evenly. Raising the attacker's weight starved the victim to about 4% of the
CPU, and a penalty weight gave the victim back about 88%. Two runs agree to
within a point.

| phase | attacker weight | victim CPU% | attacker CPU% | victim model % |
|---|---|---|---|---|
| baseline | 100 (no override) | 49.9 | 50.0 | 50.0 |
| attack | 2000 | **4.1** | 95.9 | 4.8 |
| penalty | 10 | **87.6** | 12.3 | 90.9 |

This is the recorded run (`docs/scx-qmap-demo.cast`; replay with
`asciinema play docs/scx-qmap-demo.cast`). Each value is the mean of three 3 s
windows; the per-window samples are in the recording. An earlier, unrecorded
run gave victim 50.5 / 4.1 / 87.8 and attacker 49.4 / 95.8 / 12.2.

This is functional evidence from a VM. Per CLAUDE.md, headline scheduling
numbers still come from the simulation.

## How it mirrors the simulation

In the sim, `weight = claimed_priority * demand * multiplier`, and weights
become proportional CPU shares (`sim/policies/base.py`). An ML policy that flags
a process multiplies its weight by `penalty = 0.1` (`sim/policies/ml.py`). The
demo runs the same three steps on a real kernel:

- **baseline**: both workers at the default weight 100, an even split.
- **attack**: the attacker claims weight 2000 (the sim's hog), and the victim
  starves.
- **penalty**: the attacker drops to weight 10 (the sim's 0.1x multiplier on
  the default weight), and the victim recovers.

The model column is that proportional share, `w_v / (w_v + w_a)`, with the
patch's slice clamps applied.

What it does not show: the penalty is applied by hand here, as if a detector
had flagged the attacker. In the sim, mimicry is exactly what stops the ML
policies from applying it, and the reservations do not need it. This demo
validates the mechanism (a per-PID weight sets CPU share through sched_ext), not
the detection.

## The change (`kernel/scx_qmap_pidweight.patch`)

A diff against Linux v7.0 `tools/sched_ext`: 2 files, +55 / -6.

- **`pid_weight` map:** `BPF_MAP_TYPE_HASH`, key `pid_t`, value `u32`, 1024
  entries, `LIBBPF_PIN_BY_NAME`, so libbpf pins it at `/sys/fs/bpf/pid_weight`
  on load. The key is the tgid (the PID userspace sees), so all threads of a
  process share one weight.
- **`task_slice(p)`:** returns `slice_ns * weight / 100`, clamped to
  [200 us, 1 s], or `slice_ns` unchanged if the PID is not in the map. The 1 s
  cap stays well under scx_qmap's 5 s watchdog. It replaces `slice_ns` at the
  four `scx_bpf_dsq_insert()` calls that used it.
- **Userspace:** a `nr_pidw_hits` counter, shown as `pidw=` in scx_qmap's stats
  line, which confirms the map is being read. scx_qmap also prints the pin path
  and unpins the map on exit, so stale weights never carry into the next run
  (PIDs get reused).

**Why the slice and not the FIFOs:** stock scx_qmap picks one of five FIFOs from
the task's weight, but a task allowed on only one CPU never reaches them.
`pick_direct_dispatch_cpu()` returns `prev_cpu` whenever
`nr_cpus_allowed == 1`, so both the wakeup path (`select_cpu`) and the
slice-expiry path (`enqueue`) send a pinned task straight to the CPU's local
queue with a flat `slice_ns`. Two `taskset -c 0` workers just take turns, so the
slice is the knob that reaches them. With two always-runnable tasks alternating,
CPU share follows the slice ratio directly.

## Box

Same VM as the #10 spike (`docs/kernel-spike.md`): Multipass 1.17.0 (`hcs`
driver) on a Windows 11 Pro desktop (Intel Core i7-10700KF). Guest is Ubuntu
26.04.1 LTS x86-64, 2 vCPU, 2 GB RAM, kernel `7.0.0-43-generic`
(`CONFIG_SCHED_CLASS_EXT=y`, `CONFIG_HZ=1000`). scx_qmap was built from the
Linux `v7.0` tree (`028ef9c9`) with clang 21.1.8. bpftool is 7.7.0 with
libbpf 1.7.

## Reproduce

On a sched_ext box (see `docs/kernel-spike.md`), from a clone of this repo:

```bash
sudo bash scripts/scx_qmap_demo.sh 2>&1 | tee /tmp/scx_qmap_demo.out
```

The script:
1. Fetches the Linux tree matching `uname -r` into `/var/tmp/kernel-spike`, or
   uses `KTREE=...` if you set it.
2. Applies the patch if it isn't applied yet, and builds `scx_qmap`.
3. Loads it and starts `victim` and `attacker` with `taskset -c 0`.
4. Runs the three phases, prints the table, and unloads the scheduler.

You can override `WINDOW`, `WINDOWS`, `ATTACK_WEIGHT` and `PENALTY_WEIGHT` from
the environment. The script exits non-zero unless the victim falls below half
its baseline in the attack phase and more than doubles back under the penalty.

To set weights by hand while the patched scx_qmap runs:

```bash
sudo scripts/scx_pid_weight.sh 8894 2000   # = bpftool map update pinned /sys/fs/bpf/pid_weight \
                                           #     key 190 34 0 0 value 208 7 0 0 any
sudo scripts/scx_pid_weight.sh 8894 clear  # back to stock scx_qmap behavior
sudo scripts/scx_pid_weight.sh show        # bpftool map dump (BTF pretty-prints pid and weight)
```

To record the run: `asciinema rec -c "sudo bash scripts/scx_qmap_demo.sh" demo.cast`.
Always give a file name; without one, `asciinema rec` uploads to asciinema.org.

## Notes

- **Gaps to the model:** the attack phase is within 1 point of the model and the
  penalty phase about 3 points off. The model ignores the scheduler tick:
  slices end on the 1 ms tick (`HZ=1000`), which stretches a 2 ms slice
  proportionally far more than a 20 ms one. That is likely why the penalized
  attacker gets 12% rather than 9%. The model also leaves out the per-CPU kernel
  threads that share CPU 0.
- **CPU placement:** the script pins itself and scx_qmap to CPU 1, so the only
  contenders on CPU 0 are the two workers and per-CPU kernel threads. It needs
  2+ CPUs.
- **Timing of a change:** a new weight takes effect at the task's next slice
  (at most 1 s later). The script waits 1 s after each change before sampling.
- **Measurement:** CPU% is the utime+stime delta from `/proc/<pid>/stat` over
  wall time. With USER_HZ = 100, that is 10 ms resolution, about 0.3% over a 3 s
  window.
- **Other schedulers:** the script stops the `scx` package's `scx.service` and
  refuses to run if another sched_ext scheduler is already loaded, the same
  gotcha the #10 spike hit.
