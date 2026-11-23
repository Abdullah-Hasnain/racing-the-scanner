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
cp .env.example .env
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

## Aqua Tracee (Member 3)

Install the Tracee binary (see the Aqua docs) and run it against a target:
```bash
sudo tracee --policy ../detection/tracee/memory-hiding.yaml --output json
```
The aggregator and triage work offline on a saved log, so you can start before
Tracee is set up.

## Installing scx (for the real-kernel validation, stretch)

On Ubuntu 25.04+: `sudo apt install scx-scheds`, then `scx_simple` and check
`cat /sys/kernel/sched_ext/state`. On Arch: the `scx-scheds` package. Loading a
scheduler needs root.
