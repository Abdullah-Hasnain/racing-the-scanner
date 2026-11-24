# Kernel validation spike (M3, #10)

Goal: confirm a `sched_ext` (scx) scheduler loads on a real Linux 6.12+ kernel.
This is the stretch milestone. If it does not load, the simulation remains the
deliverable and that is a valid, documented outcome.

Run `scripts/kernel_spike.sh` on an x86-64 cloud VM (a real VM, not a container),
then paste its output into the sections below.

## Box
- provider / instance type:
- distro (want Ubuntu 25.04 plucky, whose generic kernel ships sched_ext):
- `uname -r`:
- arch: x86-64

## Kernel sched_ext support
Paste the config / sysfs check (want `CONFIG_SCHED_CLASS_EXT=y` and
`/sys/kernel/sched_ext` present):

```
(paste)
```

## scx install
- command: `sudo apt install -y scx`
- version:

## scx_simple load
Paste the confirm block captured while it ran:

```
grep ext /proc/self/sched           -> ext.enabled : 1
cat /sys/kernel/sched_ext/state      -> enabled
cat /sys/kernel/sched_ext/root/ops   -> simple
cat /sys/kernel/sched_ext/enable_seq -> (nonzero)
scx_simple stdout                    -> local=.. global=..
```

## Outcome
- [ ] PASS: `scx_simple` loaded (`enable_seq` > 0). sched_ext works on this box;
      the mechanism behind the invariant exists in a real kernel. Proceed to #11.
- [ ] FAIL: did not load (reason: ______). The simulation is the deliverable.

## Notes / gotchas
- 6.12+ is necessary but not sufficient: the kernel must be built with
  `CONFIG_SCHED_CLASS_EXT=y`. A stock kernel can be newer and still lack it.
- On Ubuntu 24.04 use the PPA kernel: `ppa:arighi/sched-ext`, then
  `sudo apt install -y linux-generic-wip scx` and reboot.
- Timing inside a VM is noisy; this spike only asks whether scx loads, not for
  headline scheduling numbers (those come from the simulation).
