# Setup: GPU and CUDA (the NVIDIA machines)

Only needed for the optional neural autoencoder policy and for
running the local LLM used by the Tracee triage. Everything else is CPU-only.

## Drivers and CUDA

1. Install the current NVIDIA driver for your card (RTX 5070 Ti, GTX 1660 Super).
2. Verify: `nvidia-smi` shows the GPU and a CUDA version.

## torch with CUDA

Install core deps first, then the matching torch build:

```bash
pip install -r requirements.txt
# pick the index URL matching your CUDA (example for CUDA 12.x):
pip install torch --index-url https://download.pytorch.org/whl/cu124
pip install -r requirements-gpu.txt   # xgboost, lightgbm
```

Verify:
```bash
python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))"
```

No setting is needed: when torch is installed the sweep includes the autoencoder
policy, and it runs on the GPU whenever `torch.cuda.is_available()`.

## Local LLM for Tracee triage (D3)

Run a local model so nothing leaves the machine:

```bash
# Ollama (simplest): install from ollama.com, then
ollama pull llama3.1:8b
ollama serve          # serves on http://localhost:11434
```

The triage reads these environment variables (defaults shown; see `.env.example`):
```
RTS_LLM_URL=http://localhost:11434
RTS_LLM_MODEL=llama3.1:8b
```

The RTX 5070 Ti (32 GB) can run a larger model than the 1660 Super; pick the
model size to fit. If no LLM is reachable, `triage_llm.py` falls back to a
transparent heuristic so the pipeline still runs.
