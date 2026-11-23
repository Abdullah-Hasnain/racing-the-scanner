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
