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
| S3 | invariant | hard CPU-reservation floor |

All ML policies share one harness: same features in, a priority multiplier out.
That is why 15 of them is a model sweep, not 15 projects. Expected result: under
mimicry the ML policies are evaded (they cannot tell the disguised hog apart from
a benign app), while the invariant holds.

### The 15 ML policies: calibration and behavior

Every policy sees the same six timing features per process per tick. Unsupervised
detectors are trained on legitimate windows only (benign apps + monitor) and
demote an outlier to x0.1. Supervised classifiers are trained on {normal, naive
hog, monitor}; they demote a predicted hog to x0.1 and boost the predicted
monitor to x2.

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
demotes the naive hog on 100% of windows and the mimic on 0-1%: the mimic sits at
the center of the benign population, which is the least anomalous place a
process can be.
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

**Known limitation (tracked in #7).** Catching the hog is not yet enough to
protect the monitor. With penalty x0.1, a demoted naive hog keeps weight 1.5
against the monitor's 0.25, so the unsupervised family misses the 8-tick window
even when detection is perfect. Even with no attacker at all, the benign load
alone holds the monitor at about 9 ticks. Until the scenario is rebalanced,
naive vs mimicry does not isolate mimicry's effect.
