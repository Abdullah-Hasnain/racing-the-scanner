# Architecture

## The one idea

A live RAM scanner catches a hiding process only during the few milliseconds it
exposes a page. The scanner needs CPU to run, so the scheduler decides whether
it runs in time. **Detection is a race for CPU.** The attacker hides its memory
*and* starves the scanner of CPU (while faking benign timing so a smart
scheduler does not throttle it). We compare scheduling frameworks on whether
they keep the scanner running in time, and pair the winner with Tracee + local
AI triage to keep false alarms down.

## The three layers

```
             attacker                                   defenders
  +-----------------------------+        +-------------------------------------+
  | memory hiding  (V1..V4)      |  --->  | D1 live RAM scanner                 |
  |   mprotect/uffd/memfd_secret |        | D2 Aqua Tracee (default vs custom)  |
  | scheduler abuse (mimicry)    |        | D3 Tracee + local-LLM triage        |
  +-----------------------------+        +-------------------------------------+
               |                                          ^
               v                                          |
        +--------------------------------------------------------+
        |  scheduling framework under test (the comparison)      |
        |  S0 baseline EEVDF | ~15 ML-augmented | S3 invariant   |
        +--------------------------------------------------------+
```

- **memory/** (Khan): the hiding payloads and the scanner. Linux.
- **sim/** (Hasnain): the scheduling comparison. The attacker shapes timing to
  evade the ML schedulers; the invariant resists because it reserves CPU without
  judging anyone. Pure Python, runs anywhere. This is the core deliverable.
- **detection/** (Ibad): Tracee + AI triage + the integrated evaluation.

## Why a simulation is the core

The scheduling question (can the monitor keep running in time) is a well-defined
allocation problem. Modelling it in userspace lets us sweep ~15 policies cheaply
and reproducibly, with no kernel, verifier, or VM noise. A subset (baseline, one
ML policy, invariant) is then validated on real `sched_ext` to ground it. See
ROADMAP for the stretch path.

## The scheduling policies

| id | policy | family |
|----|--------|--------|
| S0 | baseline | stock EEVDF (control) |
| S2 | iforest, ocsvm, lof, elliptic, knn, hbos, gmm, autoencoder | unsupervised anomaly |
| S2 | rf, histgb, logreg, svm_rbf, mlp, knn_clf, naive_bayes | supervised classifier |
| S4 | sched_fifo, cgroup_cpumax, cgroup_weight, sched_deadline | standard Linux reservation (detection-free) |
| S3 | invariant | hard CPU-reservation floor |

All ML policies share one harness: same features in, a priority multiplier out.
That is why 15 of them is a model sweep, not 15 projects. Expected result: under
mimicry the ML policies are evaded (they cannot tell the disguised hog apart from
a benign app), while the invariant holds. The reservation group answers "why not
just use real-time priority or cgroups?" (see "Standard reservation baselines").

### The 15 ML policies: calibration and behavior

Every policy sees the same six timing features per process per tick. Both
families respond the same way: demote a suspected hog to x0.1 and boost the
monitor to x2. Unsupervised detectors are trained on legitimate windows only
(benign apps + monitor); they demote an outlier and boost the monitor by role,
unless they flag the monitor itself. Supervised classifiers are trained on
{normal, naive hog, monitor}; they demote a predicted hog and boost the
predicted monitor. See "Scenario balance" below.

**How the hyperparameters were chosen.** Values live in `sim/policies/ml.py`.
They were calibrated for the default scenario (`sim/config.yaml`) using held-out
**legitimate** behavior only: benign apps never seen in training, fresh monitor
windows, and the naive hog. Validation seeds were disjoint from the sweep seeds,
and the mimicry attacker was never used. The rule:
- One shared operating point, `CONTAM = 0.01`: each detector flags 1% of clean
  training windows.
- Hard constraints: the naive hog is demoted on at least 99% of windows and the
  monitor on at most 5%.
- Within each model's standard range, pick the value with the fewest false
  positives on unseen benign apps. Ties within 0.02 go to the candidate fewest
  grid steps from the scaffold's original value.

Reproduce the choices with `python -m sim.calibrate` (the rule is encoded there).

If the scenario changes (`train_samples`, `n_benign`, or the profiles), re-check
the calibration. Unseen-app false positives (FP) below are from 12 validation
seeds.

**Unsupervised anomaly detectors** (trained on legit behavior only). Each of them
demotes the naive hog on 100% of windows and the mimic only at its false-positive
rate (per-run median 0-3%; single runs up to 14% for `lof` and 20% for `hbos`):
the mimic sits at the center of the benign population, which is the least
anomalous place a process can be.
- `iforest`: Isolation Forest (random-partition ensemble). Keys on how few
  random splits isolate a window; 100 trees. FP 10%, monitor 3%. At the old
  contamination of 0.06 it punished the monitor 16% of the time, because a small,
  separated cluster is easy to isolate.
- `ocsvm`: one-class SVM (kernel boundary). Keys on falling outside an RBF
  boundary around legit data; `nu=CONTAM`, `gamma=0.01`. The old
  `gamma="scale"` wrapped each training app tightly (48% FP with the old
  `nu=0.06`, 42% at `nu=0.01`); the wide kernel gives 16%.
- `lof`: Local Outlier Factor (local density). Keys on a window's density
  relative to its 200 nearest neighbors. k stays below the 300-window monitor
  cluster so the monitor is never the outlier. Still 39% FP: local density
  memorizes the 4 training apps.
- `elliptic`: robust Gaussian envelope (MCD covariance + Mahalanobis distance).
  Uses the default robust fit; the old `support_fraction=0.95` was effectively
  non-robust (50% FP, and 37% even at `CONTAM=0.01`, vs 5% now). The mimic sits
  at the center of the ellipsoid.
- `knn`: distance to the k-th nearest training window (k=200; the training
  threshold now excludes each point's match with itself). 35% FP, for the same
  memorization reason as `lof`.
- `hbos`: histogram-based outlier score (sum of per-feature log-densities,
  6 bins). Coarse bins generalize: 2.5% FP, vs 11% at 10 bins. It ignores feature
  correlations and flags the monitor (4%) more than benign apps, because the
  monitor's values are the minority in every marginal histogram.
- `gmm`: Gaussian mixture likelihood, calibrated to 1 component (diagonal). Each extra component
  locks onto one training app and roughly doubles FP (7% at n=1, 18-20% at n=2,
  73% at the old n=3 full). The mimic gets the highest likelihood there is.
- `autoencoder` (optional, needs torch): reconstruction error of a
  6-8-4-8-6 network, 60 epochs, seeded. 24% FP (27% at the original latent 3);
  training longer memorizes the training apps. The mimic reconstructs like any
  benign app.

**Supervised classifiers** (trained on {normal, naive hog, monitor}). Across
their grids, all seven reach about 100% on held-out monitor and naive-hog
windows, and the chosen settings mislabel at most about 3% of unseen benign
windows (as the monitor), so values stay at or near library defaults. They therefore produce identical
schedules: they boost the monitor x2 and wave the mimic through as normal.
Because the mimic's timing is drawn from the normal class, no decision surface
can separate it.
- `rf`: random forest of 120 trees (axis-aligned splits). Accuracy is flat from
  50 trees up.
- `histgb`: histogram gradient boosting with sklearn defaults. Early stopping
  helped inconsistently across seeds, so it is left off.
- `logreg`: multinomial logistic regression (linear boundaries), C=1.
- `svm_rbf`: RBF-kernel SVM, C=1, `gamma="scale"`.
- `mlp`: two-layer network (32, 16). Converges in under 100 iterations; early
  stopping is off because it starved the small net of data (monitor recall
  fell to 32%).
- `knn_clf`: majority vote of the 7 nearest training windows.
- `naive_bayes`: per-class independent Gaussians.

**Overhead.** `run_once` pins BLAS/OpenMP to one thread, and the estimators set
`n_jobs=1`. `overhead_ms` is therefore the single-core cost of a decision,
summed over a run. Without the pin, OpenMP thread wake-ups inflated `histgb`
about 10x (13 ms to 1 ms per decision).

### Scenario balance (#7)

The scenario is set so that detection decides the outcome: a scheduler that
catches the hog protects the monitor, and one that is fooled does not. A
process's weight is `claimed_priority x demand x multiplier`, and the monitor
needs a share of at least 1/8 to finish a scan inside the 8-tick window. The
weights are: monitor 0.5, four benign apps 2.0 in total, and the hog 15 (1.5
once demoted x0.1).

| condition | monitor share | ticks per scan |
|---|---|---|
| no attacker, any policy without a boost | 0.5 / 2.5 = 20% | 5 |
| naive hog, baseline (undefended) | 0.5 / 17.5 = 2.9% | 35 |
| naive hog, detected by either ML family | 1.0 / 4.5 = 22% | about 4.5 |
| mimic, undetected (boost applied) | 1.0 / 18 = 5.6% | 18 |
| invariant, any condition | at least 20% | at most 5 |

So detected means protected, mimicry means starved, and the invariant is always
safe. Before #7 the monitor's demand was 0.25: the benign load alone held it at
about 9 ticks, and the unsupervised family, which only demoted outliers, missed
the window even with perfect detection.

The unsupervised boost is given by role and kept by behavior. The scheduler
knows which process is the monitor, but a window that the detector flags is
demoted x0.1 instead, so each false positive on the monitor costs it a tick.
The boost is a multiplier, not a reservation: a hog that is not demoted still
outweighs it. Only S3 guarantees a share. Demand and multipliers are not
observed features, so the #6 calibration still holds; `python -m sim.calibrate`
picks the same values. `sim/tests/test_scenario.py` guards all of this.

### Attack conditions (G3)

`SimConfig.condition` (CLI `--condition`) separates the two halves of the attack:

| condition | attacker | a scan catches it if |
|---|---|---|
| `none` | absent | latency <= 8 (measures the monitor's timeliness only) |
| `hiding` | hides; benign timing and a benign app's share | latency <= 8 |
| `starvation` | hogs the CPU (naive or mimic timing); never hides | any scan completes |
| `coupled` (default) | hides and hogs | latency <= 8 |

`python -m sim.run_experiment --policies all --g3` runs every condition in both
attacker modes and writes `results/aggregate_g3.csv` (and `per_run_g3.csv`),
keyed by `condition`, `mimicry`, `policy`, and `group`. `mimicry` only changes
anything where the attacker hogs. Every condition uses the same detector
training (legit behavior plus the naive hog), so the attacker is blind to the
trained detector and the mimic never appears in training. Expected shape: hiding
alone is caught because the scanner runs on time, starvation alone is caught
because nothing is hidden, and only the coupled attack beats an undefended or
fooled scheduler.

### Detection ROC-AUC (#8)

The multiplier shows what a scheduler *did*; the ROC-AUC shows what its detector
can *see*, independent of any threshold. Besides its multiplier, every ML policy
exposes a continuous score per process (`Policy.scores`, higher = more
hog-like):
- unsupervised: the detector's own outlier statistic, the quantity its
  `outlier_mask` thresholds. That is the negated `decision_function` for
  `iforest`, `ocsvm`, `lof`, and `elliptic` (the same rule as their `predict`),
  the k-th neighbor distance for `knn`, the HBOS score, the negative
  log-likelihood for `gmm`, and the reconstruction error for `autoencoder`.
- supervised: P(hog). `svm_rbf` gives its one-vs-rest decision value for the hog
  class instead, since SVC has no probabilities without Platt scaling (extra
  internal CV fits); ROC-AUC only needs the ranking.

Baseline and invariant have no detector, so their AUC is empty (n/a).

**Test set, and why it does not leak.** After each run the policy scores every
window the scheduler judged during it, in one batch: in tick order, nothing
shuffled or dropped, outside the overhead timer, and without drawing random
numbers, so the scheduling metrics are bit-identical to before. These windows
are held out from training by session, not by shuffling windows: training uses
its own processes, the run's benign apps are new processes never seen in
training, and the monitor's and attacker's windows are fresh draws.
`test_auc_windows_are_held_out_by_session` checks all of this, and fails if a
training app is reused or the windows are shuffled.

The attacker's windows are the positives. There are two sets of negatives:
- `roc_auc`: benign apps and the monitor (all legitimate processes).
- `roc_auc_benign`: benign apps only. This isolates the mimicry question (can the
  detector tell the attacker from the apps it imitates?) from the monitor, which
  is easy to rank because its timing is far from any hog's.

Both are empty where there is no attacker (`none`). Values are reported raw:
below 0.5 means the detector scores the attacker as *more* normal than the
negatives. They are never flipped to 1 - AUC.

**Results** (default scenario, 20 runs; median, with the range over runs):

| policies | naive hog, both columns | mimic, `roc_auc` | mimic, `roc_auc_benign` |
|---|---|---|---|
| 7 unsupervised | 1.00 (min 0.9996) | 0.15-0.35 | 0.18-0.34 |
| `rf`, `knn_clf` | 1.00 | 0.50 | 0.50 |
| `histgb`, `svm_rbf` | 1.00 | 0.24, 0.39 | 0.28, 0.29 |
| `logreg`, `mlp`, `naive_bayes` | 1.00 | 0.64-0.68 (runs 0.26-0.945) | 0.55-0.61 (runs 0.07-0.93) |

How to read the mimic column:
- **Below chance is the finding.** The mimic sits at the exact center of benign
  behavior, while every real app is offset from that center by its own jitter.
  A detector that scores distance or density therefore finds the mimic more
  normal than the apps it imitates. A defender cannot exploit this without
  training on mimics, which would make the result tautological.
- **`rf` and `knn_clf` give exactly 0.5.** All trees (or all 7 neighbors) vote
  "normal" for both the mimic and the benign apps, so every pair ties.
- **`logreg`, `mlp`, and `naive_bayes` rank the mimic above chance, but never act
  on it.** Part of the lift is the monitor: it sits even further from the hog
  class than the mimic, so `roc_auc` is 0.08-0.09 higher than `roc_auc_benign`.
  The rest is a sub-threshold ranking against benign apps. Its sign depends on
  which side of the mimic a run's 4 benign apps happen to fall, hence the wide
  spread. The probabilities are far from any decision: `naive_bayes` gives the
  mimic P(hog) of about 1e-216 against 1e-242 for benign apps, and `logreg`
  2e-4 against 1e-4. No supervised policy demoted the mimic on any tick in any
  run, which is why the monitor still misses 100% of scans.

Across the G3 conditions, `starvation` matches `coupled` (same attacker). In
`hiding` the attacker uses the mimic's benign-center timing in both modes, so its
AUC equals the mimic's. The scheduler's detector cannot see a hider that does
not hog; catching it is the scanner's job.

The tests encode these results with caps taken from the 20-run spread
(`sim/tests/test_metrics.py`):
- naive hog: every policy >= 0.99 (observed minimum 0.9996);
- mimic, family: the median `roc_auc_benign` across the ML policies is <= 0.5
  (it ranged 0.14-0.41 per run);
- mimic, each policy: both columns <= 0.95 (maximum over all 280 runs 0.945,
  `naive_bayes`);
- mimic, decisions: supervised policies demote it on 0% of ticks, unsupervised
  ones on at most 25% (worst run 20.5%, `hbos`), against >= 99% for the naive
  hog.

### Spread across runs (#8)

Every aggregate CSV (`aggregate_{mimicry,naive}.csv`, `aggregate_<condition>_<mode>.csv`,
`aggregate_g3.csv`) holds the median across `--runs`. `p95_latency`, `miss_rate`,
`roc_auc`, and `roc_auc_benign` also get `<metric>_q25` and `<metric>_q75`, the
interquartile range across runs; `run_experiment` prints them as
`median [q25, q75]`. The IQR describes run-to-run variation over seeds. It is not
a confidence interval on the median.

Under mimicry every ML policy's miss rate is median 1.0, IQR 1.0-1.0. A few
single runs dip below that: `lof` in 4 of 20 runs (down to 0.85), and `hbos` and
`knn` in one run each (0.78, 0.98). In those runs false positives happened to
demote the mimic on some ticks. That is false-positive noise, not detection; see
the demotion rates under "Unsupervised anomaly detectors" above.

### Standard reservation baselines (#9)

The reservation group (`sim/policies/reservation.py`) models the standard Linux
CPU-reservation mechanisms, so the comparison answers "why not just use
real-time priority or cgroups?". They are detection-free: they protect the
known monitor, or bound everyone else, without classifying any process. Every
multiplier is 1 and there is no score, so mimicry cannot affect them: naive and
mimicry runs are identical, and their AUC is n/a. They act through
`Policy.allocate`, which rewrites the proportional shares each tick. The
invariant's floor moved to that hook too, with its arithmetic unchanged.

All four are fluid models, and they rely on the monitor being always runnable
(it scans back to back):

| policy | mechanism | sim model |
|---|---|---|
| `sched_fifo` | SCHED_FIFO real-time priority for the monitor | The monitor takes `rt_limit` = 95% first. The kernel keeps about 5% of each second for normal tasks (RT throttling, or the fair-server reservation on newer kernels). Normal tasks, the hog included, share the rest by weight. |
| `cgroup_cpumax` | cgroup v2 `cpu.max`, the same cap on every non-monitor process | Each non-monitor process may use at most `cpumax_cap` = 20%: an equal fifth of the CPU for the five tenants (four apps and the attacker). The CPU is shared by weight; a process over its cap is held at it, and the excess goes to the others. |
| `cgroup_weight` | cgroup v2 `cpu.weight`: the monitor in its own cgroup, everyone else in a sibling | Weights 25:100 give the monitor exactly 20% (`floor_share`); the rest split by weight inside the other group. |
| `sched_deadline` | SCHED_DEADLINE, runtime/period = 0.2 | The same 20:80 split as `cgroup_weight`. The row is kept for completeness and is identical to it. |

`cgroup_cpumax` caps everyone equally on purpose. Capping only the attacker
would need an oracle that knows which process it is. At this cap it would also
give the same allocation, because no benign app reaches 20%, so no oracle
variant is included.

**Results, coupled attack** (20 runs, median; naive and mimicry are identical):

| policy | p95 latency | miss rate | monitor share | benign share |
|---|---|---|---|---|
| `sched_fifo` | 1.6 (a scan every 1-2 ticks) | 0 | 95% | 0.6% |
| `cgroup_weight`, `sched_deadline`, `invariant` | 5 | 0 | 20% | 9.4% |
| `cgroup_cpumax` | 7 | 0 | 16% | 64% |
| `baseline` (for reference) | 35 | 1.0 | 2.9% | 11.4% |

`benign_share` is the combined CPU share of all benign apps (mean over ticks),
reported for every policy. It shows each mechanism's cost:
- **`sched_fifo` has the lowest monitor latency of any policy, and it nearly
  starves the system.** The benign apps get 0.6% of the CPU, because the hog
  takes most of the 5% that real-time priority leaves over. That is why a busy
  scanner does not run as SCHED_FIFO in production.
- **The invariant is a standard reservation, not a new primitive.** A 25:100
  `cpu.weight` split and a fluid 0.2 SCHED_DEADLINE budget are numerically
  identical to it in every condition and mode (asserted in
  `sim/tests/test_reservation.py`). This holds because the monitor is always
  runnable and its proportional share never exceeds 20% under a policy that
  judges no one. These 20% reservations protect only the monitor: the hog still
  takes about 71% of the CPU, and the benign apps get 9.4%.
- **`cpu.max` is coarser, and it depends on the cap.** The monitor is protected
  only by what the caps leave over. At 20% per tenant it gets 16%, safe with one
  tick to spare (p95 7 against the window of 8). A looser cap fails (coupled
  mimicry, 20 runs, median):

  | cap per process | 0.15 | 0.20 (default) | 0.25 | 0.30 | 0.35 | 0.40 | 0.50 |
  |---|---|---|---|---|---|---|---|
  | monitor p95 | 4 | 7 | 7 | 8 | 8 | 9 | 10 |
  | miss rate | 0 | 0 | 0 | 0 | 0 | 0.32 | 1.00 |

  It is also the only mechanism here that contains the hog: the benign apps keep
  64% of the CPU.
