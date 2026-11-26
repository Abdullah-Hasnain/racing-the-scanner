# Setup: Linux / WSL (the systems pieces)

This is where `memory/`, the scanner, Tracee, and real `sched_ext` run.

## Base tools

```bash
sudo apt update
sudo apt install -y build-essential clang make python3 python3-venv python3-pip git
```

## Python

```bash
cd racing-the-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
make test
```

## Build and run the memory payloads

```bash
cd memory
make                    # builds bin/v1 .. bin/v4
./bin/v1                # prints its PID; leave it running
# in another terminal:
python scanner/scanner.py --pid <PID> --interval 0.1 --duration 20
```

## Kernel requirements for the full project

- **sched_ext (scx):** mainline **kernel 6.12+**, with `CONFIG_SCHED_CLASS_EXT`.
  Ubuntu 25.04+ or Arch reach this. Verify: `grep SCHED_CLASS_EXT /boot/config-$(uname -r)`.
- **memfd_secret (V4):** kernel 5.14+. It is often disabled by default; if V4
  fails, boot with `secretmem.enable=1` and retry. Verify at runtime by running
  `./bin/v4`.
- **userfaultfd (V3):** usually available; if it errors, check
  `sysctl vm.unprivileged_userfaultfd`.

## Aqua Tracee (Ibad)

Tracee must be v0.23.2 and run from the repo root as root. The install, checksum
and exact command are in [`detection/README.md`, "Running Tracee"](../../detection/README.md#running-tracee).
The aggregator and triage work offline on a saved log, so you can start before
Tracee is set up.

## Installing scx (for the real-kernel validation, stretch)

`scx` is not in the Ubuntu archive. On Ubuntu 26.04 use the PPA:
`sudo add-apt-repository ppa:arighi/sched-ext && sudo apt install scx`. That
package ships only the Rust schedulers and auto-starts `scx_cosmos` through
`scx.service` (`sudo systemctl disable --now scx.service` to stop it).
`scx_simple` is built from the kernel tree (`tools/sched_ext`). The full steps
and the verified result are in `docs/kernel-spike.md`. On Arch: the
`scx-scheds` package. Loading a scheduler needs root.
