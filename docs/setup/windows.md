# Setup: Windows (the NVIDIA desktops and laptops)

The Windows machines do the Python work and the GPU work. The Linux systems
pieces run in WSL2 or a VM.

## Python (simulation and sweep)

Install Python 3.11+ from python.org (tick "Add to PATH"), then in PowerShell:

```powershell
cd racing-the-scanner
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env

python -m sim.run_experiment --policies baseline --runs 3 --smoke
python -m pytest -q
```

## GPU work (RTX 5070 Ti, GTX 1660 Super)

For the neural policies and the local LLM, install the CUDA-enabled torch build
and a local model runtime. See `gpu-cuda.md`. These machines also run the local
LLM for the Tracee triage (Ollama has a native Windows app).

## Linux systems pieces (memory payloads, scanner, Tracee)

Use **WSL2** with a recent Ubuntu:

```powershell
wsl --install -d Ubuntu-24.04
```

Then inside WSL follow `linux-wsl.md`. Caveat: WSL2 runs Microsoft's kernel,
which may not expose `sched_ext` or secret memory. WSL2 is fine for developing
the C payloads and the scanner; run the real `scx` validation on a dedicated
Linux boot or a cloud VM with kernel 6.12+.
