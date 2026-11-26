# Setup: macOS (Apple Silicon, M1/M2/M3)

The MacBook is your main dev machine for the Python simulation and for writing.
The C payloads, the scanner, Tracee, and real `sched_ext` need Linux, so you run
those in a Linux VM (next section).

## Python (the simulation and sweep)

```bash
# Python 3.11+ ships via Homebrew if you don't have it:
brew install python@3.12

cd racing-the-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

make sim      # smoke test
make test     # unit tests
```

That is everything you need to work on `sim/` and `analysis/`.

## Linux VM (for memory/, scanner, Tracee, scx)

Use one of:
- **OrbStack** (lightest, recommended on Apple Silicon): `brew install orbstack`,
  then `orb create ubuntu`. Fast, low overhead.
- **UTM** or **QEMU**: run an arm64 Ubuntu 25.04+ image (kernel 6.12+).

Inside the VM follow `linux-wsl.md` (same steps as Linux). Note: measuring
microsecond scheduling inside a VM is noisy; take headline scheduling numbers
from the simulation or a bare-metal/cloud x86-64 box (see the proposal's
validity note).

## Optional: torch on Apple Silicon

Only needed for the neural policies, which are optional:
```bash
pip install torch   # uses the Metal (MPS) backend automatically
```
