# Kernel validation spike (M3, #10)

Goal: confirm a `sched_ext` (scx) scheduler loads on a real Linux 6.12+ kernel.
This is the stretch milestone. If it does not load, the simulation remains the
deliverable and that is a valid, documented outcome.

Run `scripts/kernel_spike.sh` as root on an x86-64 Ubuntu VM (a real VM, not a
container), then paste its output into the sections below.

**Result: PASS** (2026-11-25). `scx_simple` loaded on kernel `7.0.0-43-generic`
and `/sys/kernel/sched_ext` confirmed it live. The output below is from
`scripts/kernel_spike.sh` run unattended on a freshly launched VM. A first,
manual run on a second VM from the same image gave the same result.

## Box
- provider / instance type: local VM, not cloud. Multipass 1.17.0 with the
  `hcs` driver (Hyper-V Host Compute Service) on a Windows 11 Pro desktop
  (Intel Core i7-10700KF, 8C/16T, 16 GB). Guest: 2 vCPU, 2 GB RAM, 10 GB disk.
- distro: Ubuntu 26.04.1 LTS (resolute). 25.04 and 25.10 are past end of life
  and Multipass no longer offers them; 26.04's generic kernel ships sched_ext.
- `uname -r`: `7.0.0-43-generic` (`#43-Ubuntu SMP PREEMPT_DYNAMIC Fri Oct 23 13:25:25 UTC 2026`)
- arch: x86-64

## Kernel sched_ext support

```
CONFIG_BPF_SYSCALL=y
CONFIG_SCHED_CLASS_EXT=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
/sys/kernel/sched_ext: present
```

## scx install
- command: `sudo add-apt-repository -y ppa:arighi/sched-ext && sudo apt install -y scx`
  (`scx` is not in the Ubuntu archive; the script adds the PPA itself)
- version: `scx 1.1.2-1`
- `scx_simple`: not in the package (Rust schedulers only), so the script builds
  it from the Linux `v7.0` tree, `make -C tools/sched_ext scx_simple`
  (clang 21.1.8; bpftool 7.7.0 / libbpf 1.7 from the same tree)

## scx_simple load
Captured while it ran (t=3s into an 8s `timeout`), plus before and after:

```
== before load ==
state:      disabled
enable_seq: 1

== confirm it is live (while running) ==
ext.enabled                                  :                    1
state:      enabled
root/ops:   simple
enable_seq: 2
switch_all: 1
tasks by ext.enabled (from /proc/*/sched):
     11   ext.enabled=0
    122   ext.enabled=1
scx_simple exit code: 124 (124 = stopped by the timeout, expected)

== scx_simple stdout ==
local=2 global=1
local=64 global=66
local=73 global=73
local=121 global=116
local=143 global=128
local=149 global=133
local=158 global=139
local=165 global=143
EXIT: unregistered from user space

== after unload ==
state:      disabled
[  395.229189] sched_ext: BPF scheduler "simple" enabled
[  403.185557] sched_ext: BPF scheduler "simple" disabled (unregistered from user space)

== RESULT ==
PASS: scx_simple loaded (state enabled, root/ops simple, enable_seq 1 -> 2). Proceed to #11.
```

`enable_seq` is already 1 before the load because installing `scx` starts its
own scheduler first (see gotchas). The 11 tasks left at `ext.enabled=0` are all
real-time threads. On the manual run they were `SCHED_FIFO` (`migration/N`,
`idle_inject/N`, `watchdogd`, `irq/9-acpi`, `psimon`, `scx_enable_helper`,
`sched_ext_helper`) plus one `SCHED_RR` (`multipathd`). sched_ext only takes
normal-class tasks; the real-time and deadline classes rank above it. So on the
real kernel, a monitor run as `SCHED_FIFO` or `SCHED_DEADLINE` bypasses whatever
sched_ext policy is loaded.

## Outcome
- [x] PASS: `scx_simple` loaded (state `enabled`, `root/ops` = `simple`,
      `enable_seq` 1 -> 2). sched_ext works on this box; the mechanism behind
      the invariant exists in a real kernel. Proceed to #11.
- [ ] FAIL: did not load (reason: ______). The simulation is the deliverable.

## Notes / gotchas
- 6.12+ is necessary but not sufficient: the kernel must be built with
  `CONFIG_SCHED_CLASS_EXT=y`. A stock kernel can be newer and still lack it.
- **Installing `scx` auto-starts a scheduler.** The package enables
  `scx.service`, which loads `scx_cosmos` (set in `/etc/default/scx`) right
  away, so sched_ext is `enabled` with ops `cosmos_1.1.5_x86_64_unknown_linux_gnu`
  before any test runs. `enable_seq` is cumulative, so "`enable_seq` > 0" alone
  is not proof that `scx_simple` loaded. The script stops the service
  (`systemctl disable --now scx.service`) and passes only if `root/ops` reads
  `simple` while it runs. Any real-kernel experiment should read
  `/sys/kernel/sched_ext/root/ops` first to know which scheduler is live.
- **`scx_simple` lives in the kernel tree now.** The `scx` package ships only
  the Rust schedulers (`scx_bpfland`, `scx_cosmos`, `scx_lavd`, `scx_rusty`,
  ...) in `/usr/sbin`, and upstream `sched-ext/scx` dropped its C examples.
  `scx_simple` and `scx_qmap` (the base for #11) are in the kernel's
  `tools/sched_ext`. In 7.0 its build compiles a bootstrap bpftool that needs
  OpenSSL headers (`libssl-dev`, for the new `sign.c`).
- PPA builds: `ppa:arighi/sched-ext` publishes `scx 1.1.2-1` for 26.04
  (resolute, amd64 and arm64) and `1.0.21~rc2-1` for 24.04 (noble). The stock
  24.04 kernel (6.8) has no sched_ext. Its PPA kernel route
  (`sudo apt install -y linux-generic-wip scx`, then reboot) was not tested here.
- Host: VT-x was disabled in firmware, which made the Multipass installer fail
  with exit 1603 (its service never started, `Error 1920`). Enabling Intel VMX
  in the BIOS fixed it. The full Hyper-V feature was not needed: the `hcs`
  driver only needs Virtual Machine Platform, which the Multipass installer
  enables (one reboot).
- Timing inside a VM is noisy; this spike only asks whether scx loads, not for
  headline scheduling numbers (those come from the simulation).
