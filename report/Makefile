# Build the report. `make` compiles main.pdf from main.tex and figures/.
# `make figures` refreshes figures/ from the repo's figures/, which
# scripts/run_demo.sh regenerates (run it first, from the repo root).
FIGS := G1_catch_rate G2_pareto G3_attack_conditions G4_policy_comparison G5_detection G6_overhead

main.pdf: main.tex $(addprefix figures/,$(addsuffix .png,$(FIGS)))
	latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex

figures:
	mkdir -p figures
	for f in $(FIGS); do cp ../figures/$$f.png figures/; done

clean:
	latexmk -C main.tex

.PHONY: figures clean
