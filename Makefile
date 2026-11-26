# Common commands. Run `make help` to see them.
# Keep this thin: it just wraps the real entry points so everyone types the same thing.

.PHONY: help setup lint test sim sweep graphs memory clean

help:
	@echo "Racing the Scanner - common commands"
	@echo "  make setup    Install core Python deps into the current environment"
	@echo "  make lint     Run ruff (same check CI runs)"
	@echo "  make test     Run the unit tests (sim, detection, and memory)"
	@echo "  make sim      Run one quick simulation (baseline policy, smoke test)"
	@echo "  make sweep    Run the full policy sweep and the G3 attack conditions"
	@echo "  make graphs   Build G1-G6 figures from the latest results/"
	@echo "  make memory   Build the C memory payloads + scanner (Linux only)"
	@echo "  make clean    Remove build artifacts (keeps results/)"

setup:
	python -m pip install -r requirements.txt

lint:
	ruff check .

test:
	pytest

sim:
	python -m sim.run_experiment --policies baseline --runs 3 --smoke

sweep:
	python -m sim.run_experiment --policies all --runs 20
	python -m sim.run_experiment --policies all --runs 20 --g3

graphs:
	python -m analysis.make_graphs

memory:
	$(MAKE) -C memory

clean:
	$(MAKE) -C memory clean || true
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache
