"""Calibrate the ML policies' hyperparameters, blind to the mimicry attacker.

Reproduces the values in sim/policies/ml.py (the rule is written up in
docs/architecture.md). Each candidate is trained exactly as the engine trains a
policy, then scored on held-out LEGITIMATE behavior only (benign apps never seen
in training, fresh monitor windows) plus the naive hog. The mimicry attacker is
never constructed here, so the sweep's headline result cannot leak into tuning.

Rule
  unsupervised  feasible if the naive hog is demoted on >= 99% of windows and the
                monitor on <= 5%; loss = share of unseen benign windows demoted.
  supervised    feasible if naive-hog recall >= 99% and the monitor is labelled a
                hog on <= 5%; loss = balanced error over {benign, monitor, hog}.
  ties          candidates within TOL of the best loss count as ties and go to
                the lowest rank (fewest grid steps from the scaffold's original
                value), then the lower loss.

Examples
  python -m sim.calibrate                          # every ML policy, 12 seeds
  python -m sim.calibrate --policies hbos gmm --seeds 4
"""

from __future__ import annotations

import argparse
import importlib.util
from collections.abc import Callable
from dataclasses import dataclass
from itertools import product

import numpy as np
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier, LocalOutlierFactor
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC, OneClassSVM
from threadpoolctl import threadpool_limits

from sim.engine import SimConfig, _build_training
from sim.policies import build_policy
from sim.policies.ml import (
    CONTAM,
    HOG,
    MONITOR,
    NORMAL,
    ClfWrap,
    GmmOutlier,
    HbosOutlier,
    KnnOutlier,
    PredictOutlier,
)
from sim.process import attacker_profile, benign_profile, monitor_profile

VAL_SEED0 = 1000        # validation seeds start here, disjoint from the sweep's 42 + run
FRESH_APPS = 10         # unseen benign apps per seed
APP_WINDOWS = 60        # observed windows per unseen app
WINDOWS = 300           # monitor and naive-hog windows per seed
MIN_HOG_CAUGHT = 0.99   # the naive hog must be demoted (or labelled a hog) this often
MAX_MONITOR_HIT = 0.05  # the monitor may be demoted (or labelled a hog) at most this often
TOL = 0.02              # losses this close to the best count as ties


# ---- held-out data ------------------------------------------------------------

@dataclass
class Fold:
    legit_X: np.ndarray   # unsupervised training set (engine's _build_training)
    sup_X: np.ndarray     # supervised training set
    sup_y: np.ndarray
    benign: np.ndarray    # windows from benign apps never seen in training
    monitor: np.ndarray
    hog: np.ndarray       # the NAIVE hog; the mimic never appears here


def make_fold(seed: int, cfg: SimConfig) -> Fold:
    rng = np.random.default_rng(seed)
    legit_X, sup_X, sup_y = _build_training(SimConfig(**{**cfg.__dict__, "seed": seed}), rng)
    apps = [benign_profile(500 + i, rng) for i in range(FRESH_APPS)]
    monitor, hog = monitor_profile(0), attacker_profile(999, mimicry=False)
    return Fold(
        legit_X, sup_X, sup_y,
        benign=np.array([a.observe(rng) for a in apps for _ in range(APP_WINDOWS)]),
        monitor=np.array([monitor.observe(rng) for _ in range(WINDOWS)]),
        hog=np.array([hog.observe(rng) for _ in range(WINDOWS)]),
    )


# ---- candidate grids ----------------------------------------------------------

@dataclass
class Grid:
    axes: dict[str, tuple]     # each axis listed in its natural order
    original: dict[str, object]  # the scaffold's value before calibration (rank 0)
    build: Callable[..., object]

    def candidates(self):
        for values in product(*self.axes.values()):
            params = dict(zip(self.axes, values, strict=True))
            rank = sum(abs(axis.index(params[k]) - axis.index(self.original[k]))
                       for k, axis in self.axes.items())
            yield params, rank


def _autoencoder(**params):
    from sim.policies.autoencoder import TorchAutoencoderOutlier

    return TorchAutoencoderOutlier(contamination=CONTAM, **params)


def grids(cfg: SimConfig) -> dict[str, Grid]:
    c = CONTAM
    # Neighbor counts stay below one process's training windows (the smallest
    # legitimate cluster), or the monitor's own cluster starts to look anomalous.
    small = cfg.train_samples
    out = {
        "iforest": Grid({"max_samples": (256, 512, 1024)}, {"max_samples": 256},
                        lambda **p: PredictOutlier(lambda: IsolationForest(
                            contamination=c, random_state=0, n_jobs=1, **p))),
        "ocsvm": Grid({"gamma": (0.002, 0.005, 0.01, 0.02, 0.05, 0.1, "scale")}, {"gamma": "scale"},
                      lambda **p: PredictOutlier(lambda: OneClassSVM(nu=c, **p))),
        "lof": Grid({"n_neighbors": tuple(k for k in (20, 50, 100, 200) if k < small)},
                    {"n_neighbors": 20},
                    lambda **p: PredictOutlier(lambda: LocalOutlierFactor(
                        contamination=c, novelty=True, n_jobs=1, **p))),
        "elliptic": Grid({"support_fraction": (None, 0.95, 1.0)}, {"support_fraction": 0.95},
                         lambda **p: PredictOutlier(lambda: EllipticEnvelope(
                             contamination=c, random_state=0, **p))),
        "knn": Grid({"k": tuple(k for k in (5, 10, 20, 50, 100, 200) if k < small)}, {"k": 5},
                    lambda **p: KnnOutlier(contamination=c, **p)),
        "hbos": Grid({"bins": (3, 4, 5, 6, 8, 10)}, {"bins": 10},
                     lambda **p: HbosOutlier(contamination=c, **p)),
        "gmm": Grid({"n_components": (1, 2, 3), "covariance_type": ("spherical", "diag", "full")},
                    {"n_components": 3, "covariance_type": "full"},
                    lambda **p: GmmOutlier(contamination=c, **p)),
        "rf": Grid({"n_estimators": (50, 100, 120)}, {"n_estimators": 120},
                   lambda **p: ClfWrap(lambda: RandomForestClassifier(random_state=0, n_jobs=1, **p))),
        "histgb": Grid({"early_stopping": ("auto", True)}, {"early_stopping": "auto"},
                       lambda **p: ClfWrap(lambda: HistGradientBoostingClassifier(random_state=0, **p))),
        "logreg": Grid({"C": (0.1, 1.0, 10.0)}, {"C": 1.0},
                       lambda **p: ClfWrap(lambda: LogisticRegression(max_iter=500, **p))),
        "svm_rbf": Grid({"C": (0.1, 1.0, 10.0), "gamma": (0.05, "scale")}, {"C": 1.0, "gamma": "scale"},
                        lambda **p: ClfWrap(lambda: SVC(kernel="rbf", **p))),
        "mlp": Grid({"hidden_layer_sizes": ((16,), (32, 16)), "early_stopping": (False, True)},
                    {"hidden_layer_sizes": (32, 16), "early_stopping": False},
                    lambda **p: ClfWrap(lambda: MLPClassifier(max_iter=800, random_state=0, **p))),
        "knn_clf": Grid({"n_neighbors": (3, 7, 15, 31)}, {"n_neighbors": 7},
                        lambda **p: ClfWrap(lambda: KNeighborsClassifier(n_jobs=1, **p))),
        "naive_bayes": Grid({"var_smoothing": (1e-9, 1e-6, 1e-3)}, {"var_smoothing": 1e-9},
                            lambda **p: ClfWrap(lambda: GaussianNB(**p))),
    }
    if importlib.util.find_spec("torch") is not None:
        out["autoencoder"] = Grid({"hidden": (8, 16), "latent": (2, 3, 4), "epochs": (60, 300)},
                                  {"hidden": 8, "latent": 3, "epochs": 60}, _autoencoder)
    return out


# ---- scoring and selection ----------------------------------------------------

@dataclass
class Row:
    params: dict
    rank: int
    metrics: dict[str, float]
    feasible: bool
    loss: float
    chosen: bool = False


def score_unsupervised(build: Callable, folds: list[Fold]) -> tuple[dict, bool, float]:
    rates: dict[str, list[float]] = {"hog_demoted": [], "monitor_demoted": [], "unseen_benign_demoted": []}
    for f in folds:
        det = build()
        det.fit(f.legit_X)
        rates["hog_demoted"].append(det.outlier_mask(f.hog).mean())
        rates["monitor_demoted"].append(det.outlier_mask(f.monitor).mean())
        rates["unseen_benign_demoted"].append(det.outlier_mask(f.benign).mean())
    m = {k: float(np.mean(v)) for k, v in rates.items()}
    ok = m["hog_demoted"] >= MIN_HOG_CAUGHT and m["monitor_demoted"] <= MAX_MONITOR_HIT
    return m, ok, m["unseen_benign_demoted"]


def score_supervised(build: Callable, folds: list[Fold]) -> tuple[dict, bool, float]:
    rates: dict[str, list[float]] = {"hog_recall": [], "monitor_recall": [], "benign_recall": [],
                                     "monitor_as_hog": []}
    for f in folds:
        clf = build()
        clf.fit(f.sup_X, f.sup_y)
        pm = clf.predict(f.monitor)
        rates["hog_recall"].append((clf.predict(f.hog) == HOG).mean())
        rates["monitor_recall"].append((pm == MONITOR).mean())
        rates["benign_recall"].append((clf.predict(f.benign) == NORMAL).mean())
        rates["monitor_as_hog"].append((pm == HOG).mean())
    m = {k: float(np.mean(v)) for k, v in rates.items()}
    ok = m["hog_recall"] >= MIN_HOG_CAUGHT and m["monitor_as_hog"] <= MAX_MONITOR_HIT
    balanced_error = 1.0 - np.mean([m["hog_recall"], m["monitor_recall"], m["benign_recall"]])
    return m, ok, float(balanced_error)


def select(rows: list[Row]) -> Row | None:
    """Lowest loss among feasible rows; ties within TOL go to the lowest rank."""
    feasible = [r for r in rows if r.feasible]
    if not feasible:
        return None
    best = min(r.loss for r in feasible)
    pick = min((r for r in feasible if r.loss <= best + TOL), key=lambda r: (r.rank, r.loss))
    pick.chosen = True
    return pick


def calibrate(name: str, grid: Grid, folds: list[Fold]) -> list[Row]:
    score = score_supervised if build_policy(name).kind == "supervised" else score_unsupervised
    rows = []
    for params, rank in grid.candidates():
        metrics, ok, loss = score(lambda p=params: grid.build(**p), folds)
        rows.append(Row(params, rank, metrics, ok, loss))
    select(rows)
    return rows


def check_registry(name: str, folds: list[Fold]) -> dict[str, float]:
    """Held-out decision rates of the policy exactly as sim/policies/ml.py builds it."""
    policy = build_policy(name)
    # Each window goes in with the process that produced it: the unsupervised
    # family boosts the monitor by role, so the policy must see roles.
    monitor, hog = monitor_profile(0), attacker_profile(999, mimicry=False)
    app = benign_profile(500, np.random.default_rng(0))
    rates: dict[str, list[float]] = {"hog_demoted": [], "monitor_demoted": [],
                                     "unseen_benign_demoted": [], "monitor_boosted": []}
    for f in folds:
        if policy.kind == "supervised":
            policy.fit(f.sup_X, f.sup_y)
        else:
            policy.fit(f.legit_X)

        def mult(X, proc):
            return policy.multipliers([proc] * len(X), X)

        rates["hog_demoted"].append((mult(f.hog, hog) < 1).mean())
        rates["monitor_demoted"].append((mult(f.monitor, monitor) < 1).mean())
        rates["unseen_benign_demoted"].append((mult(f.benign, app) < 1).mean())
        rates["monitor_boosted"].append((mult(f.monitor, monitor) > 1).mean())
    return {k: float(np.mean(v)) for k, v in rates.items()}


# ---- CLI ----------------------------------------------------------------------

def _fmt(params: dict) -> str:
    return " ".join(f"{k}={v}" for k, v in params.items())


def main() -> int:
    ap = argparse.ArgumentParser(description="Calibrate ML policy hyperparameters (mimicry-blind)")
    ap.add_argument("--policies", nargs="+", default=["all"],
                    help="policy names or 'all' (autoencoder needs torch)")
    ap.add_argument("--seeds", type=int, default=12, help="validation seeds (disjoint from the sweep)")
    args = ap.parse_args()

    cfg = SimConfig()
    available = grids(cfg)
    names = list(available) if "all" in args.policies else args.policies
    for n in names:
        if n not in available:
            print(f"[note] skipping {n}: " + ("torch not installed" if n == "autoencoder" else "unknown policy"))
    names = [n for n in names if n in available]

    chosen: dict[str, Row | None] = {}
    with threadpool_limits(limits=1):
        folds = [make_fold(VAL_SEED0 + i, cfg) for i in range(args.seeds)]
        for name in names:
            rows = calibrate(name, available[name], folds)
            cols = list(rows[0].metrics)
            print(f"\n== {name} ==")
            print("        rank  " + "  ".join(f"{c:>21}" for c in cols) + "  params")
            for r in rows:
                mark = "*" if r.chosen else ("x" if not r.feasible else " ")
                print(f"  {mark}  {r.rank:6d}  " + "  ".join(f"{r.metrics[c]:21.3f}" for c in cols)
                      + f"  {_fmt(r.params)}")
            chosen[name] = next((r for r in rows if r.chosen), None)

        print("\n== chosen (* above; x = infeasible) ==")
        for name, r in chosen.items():
            print(f"  {name:<12} {_fmt(r.params) if r else 'NO FEASIBLE CANDIDATE'}")

        print("\n== registry check: sim/policies/ml.py as built by build_policy ==")
        print(f"  {'policy':<12} {'hog_demoted':>11} {'monitor_demoted':>15} "
              f"{'unseen_benign_demoted':>21} {'monitor_boosted':>15}")
        for name in names:
            m = check_registry(name, folds)
            print(f"  {name:<12} {m['hog_demoted']:11.3f} {m['monitor_demoted']:15.3f} "
                  f"{m['unseen_benign_demoted']:21.3f} {m['monitor_boosted']:15.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
