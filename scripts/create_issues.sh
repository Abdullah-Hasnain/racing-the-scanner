#!/usr/bin/env bash
# Create the phase-1 labels, milestones, and issues with the GitHub CLI.
# Run once after the repo exists and you are authenticated (`gh auth login`).
#
#   ./scripts/create_issues.sh                       # uses the repo you're in
#   ./scripts/create_issues.sh owner/racing-the-scanner
#
# Safe to re-run: label/milestone creation tolerates "already exists".
set -euo pipefail

REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
echo "Target repo: $REPO"

label() { gh label create "$1" --color "$2" --description "$3" -R "$REPO" --force >/dev/null 2>&1 || true; }
milestone() {
  gh api -X POST "repos/$REPO/milestones" -f title="$1" -f description="$2" >/dev/null 2>&1 || true
}
issue() {  # title, body, labels, milestone
  gh issue create -R "$REPO" --title "$1" --body "$2" --label "$3" --milestone "$4" >/dev/null \
    && echo "  + $1"
}

echo "Labels..."
label "member-1" "1d76db" "Memory + scanner"
label "member-2" "0e8a16" "Scheduler sim + policies"
label "member-3" "b60205" "Detection + integration"
label "memory"   "c5def5" "memory/ module"
label "sim"      "c2e0c6" "sim/ module"
label "detection" "f9d0c4" "detection/ module"
label "stretch"  "fef2c0" "Stretch / optional"

echo "Milestones..."
milestone "M2: Core results" "The guaranteed deliverable: sim sweep, memory, detection, integration."
milestone "M3: Kernel validation" "Stretch: real sched_ext validation of a policy subset."
milestone "M4: Reservation baselines" "SCHED_FIFO, cgroup cpu.max, SCHED_DEADLINE as conditions."
milestone "M5: Write-up" "Reproduction, final README, report."

echo "Issues..."
# --- Member 1: memory ---
issue "[memory] V2: dwell-based re-locking of the previous page" \
  "Implement the dwell timer so only one page is readable at a time, and the access pattern that drives it. See memory/v2_mprotect_sigsegv.c TODO and memory/README.md." \
  "member-1,memory" "M2: Core results"
issue "[memory] V3: drop-after-use cycle for userfaultfd" \
  "After the fault handler refills a page, MADV_DONTNEED it again after a short dwell. See memory/v3_userfaultfd.c TODO." \
  "member-1,memory" "M2: Core results"
issue "[memory] Scanner: entropy checks + per-scan p50/p95/p99 CSV logging" \
  "Add Shannon-entropy checks and write per-scan latency + catch result to results/ as CSV for G1/G2." \
  "member-1,memory" "M2: Core results"
issue "[memory] G1: catch rate vs scan interval and dwell time" \
  "Sweep scan intervals (50ms-5s) and dwell times across V1-V4; plot catch rate. Wire into analysis/make_graphs.py." \
  "member-1,memory" "M2: Core results"
issue "[memory] G2: hiding-vs-slowdown Pareto + page-fault counts" \
  "Measure program slowdown vs evasion rate and page faults/sec per variant; produce the Pareto figure." \
  "member-1,memory" "M2: Core results"

# --- Member 2: sim ---
issue "[sim] Tune and validate all 15 ML policies on shared features" \
  "Confirm each of the 15 augmented policies trains and runs; tune contamination/params; document each in docs/architecture.md." \
  "member-2,sim" "M2: Core results"
issue "[sim] Naive-vs-mimicry attacker modes and the G3 conditions" \
  "Add hiding-only / starvation-only / coupled conditions so analysis can build G3. Keep the attacker blind to the trained detector." \
  "member-2,sim" "M2: Core results"
issue "[sim] Report ROC-AUC and confidence intervals across runs" \
  "Extend metrics with detection ROC-AUC and report median + IQR over runs, not single numbers." \
  "member-2,sim" "M2: Core results"
issue "[sim] Add standard reservation baselines as sim conditions" \
  "Model SCHED_FIFO, cgroup cpu.max, and SCHED_DEADLINE as scheduling conditions so the comparison answers 'why not just real-time priority or cgroups'." \
  "member-2,sim" "M4: Reservation baselines"
issue "[sim] Real-kernel spike: load scx_simple on a 6.12+ box (1-day cap)" \
  "Stand up a kernel 6.12+ VM, install scx, confirm scx_simple loads and /sys/kernel/sched_ext/state is active. Document the outcome; if it fails, the sim is the deliverable." \
  "member-2,sim,stretch" "M3: Kernel validation"
issue "[sim] Modify scx_qmap to read per-PID weights from a pinned BPF map" \
  "Minimal real-kernel demo: attacker weight up -> victim starves -> penalty -> recovers. Record it. Stretch, gated on the spike." \
  "member-2,sim,stretch" "M3: Kernel validation"

# --- Member 3: detection ---
issue "[detect] End-to-end Tracee -> aggregator -> triage harness" \
  "Script that runs an attacker + benign app, captures Tracee JSON, aggregates per-PID, triages, and reports catch + false-positive rates." \
  "member-3,detection" "M2: Core results"
issue "[detect] Benign false-alarm study (Node/Go/jemalloc), G5" \
  "Run the benign suite under Tracee default vs custom vs +AI triage; measure false alarms; produce G5." \
  "member-3,detection" "M2: Core results"
issue "[detect] mprotect flag-transition filter (PROT_NONE<->RW vs RW<->RX)" \
  "Refine the aggregator/policy so JIT (RW<->RX) is separated from hiding (PROT_NONE<->RW)." \
  "member-3,detection" "M2: Core results"
issue "[detect] Integrated coupled-attack evaluation + overhead (G3, G6)" \
  "Couple hiding + starvation across scheduling policies; measure AI-triage and scheduler overhead for G6." \
  "member-3,detection" "M2: Core results"

# --- shared ---
issue "[docs] run_demo.sh reproduction + final README pass on a clean clone" \
  "Verify one-command reproduction and that a fresh clone sets up from the README with no troubleshooting." \
  "member-3" "M5: Write-up"

echo "Done."
