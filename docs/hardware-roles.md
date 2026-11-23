# Hardware roles

Five machines, very different capabilities. The rule: the Python simulation runs
anywhere, the Linux systems work needs a Linux 6.12+ box, and the GPU/LLM work
goes to the NVIDIA machines. Nobody waits on a machine they do not have.

| Machine | Owner | Role | Runs |
|---------|-------|------|------|
| RTX 5070 Ti, 32 GB | Ibad (desktop) | Heaviest compute | neural policies (autoencoder, LSTM, CNN), local-LLM triage, large sweeps |
| GTX 1660 Super, 16 GB | you (desktop) | Moderate GPU | secondary neural/LLM work, parallel sweep shards, benign-suite runs |
| MacBook Pro M1 Pro | you | Dev + build | coding, the Python sim, and the Linux VM for memory/kernel testing |
| Laptop, 16 GB | Khan | Lightweight | the CPU model sweep (sklearn is fine), docs, reviews, PM |
| Laptop (similar) | Ibad | Lightweight | benign-workload runs, testing, issue triage, report |

## What needs what

- **Pure Python (sim, sklearn sweep, analysis):** any machine, no GPU, no Linux.
  This is deliberate so all three of you can work in parallel from day one.
- **Linux kernel 6.12+ (memory payloads, scanner, Tracee, real scx):** a VM
  (UTM/QEMU/OrbStack on the Mac; VirtualBox/Hyper-V on Windows) or a dedicated
  Linux boot. See `setup/linux-wsl.md`. WSL2 is fine for the C payloads and the
  scanner but may lack sched_ext; use a real VM or cloud box for scx.
- **NVIDIA GPU (neural policies, local LLM):** Ibad's RTX 5070 Ti first, the GTX
  1660 Super second. See `setup/gpu-cuda.md`. Every neural policy is optional and
  has a CPU fallback, so no one is blocked without a GPU.

## Parallelism

The three layers (memory, sim, detection) have clean interfaces and almost no
shared files, so the three members rarely block each other. Within the sim, the
15-model sweep shards trivially across machines: each runs a subset of policies
and the CSVs are concatenated for the graphs.
