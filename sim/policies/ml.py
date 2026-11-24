"""The ML-augmented scheduling policies (the ~15 "augmented schedulers").

They all share one harness: each takes the same observed feature windows and
returns a priority multiplier per process. Swapping the model is a one-line
change, which is exactly why a 15-model sweep is feasible for a small team.

Two families:
- unsupervised anomaly detectors: trained on legitimate behavior only (benign
  apps + the monitor), they penalize processes whose timing looks anomalous.
  A mimicry attacker sits inside the benign distribution and is not penalized.
- supervised classifiers: trained to label {normal, hog, monitor}, they demote
  hogs and boost the monitor. Mimicry makes the hog classify as normal.

Every model here is pure scikit-learn (CPU, in requirements.txt) except the
autoencoder, which is torch and optional (requires_torch=True).
"""

from __future__ import annotations

from collections.abc import Callable

import numpy as np
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.mixture import GaussianMixture
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import (
    KNeighborsClassifier,
    LocalOutlierFactor,
    NearestNeighbors,
)
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC, OneClassSVM

from sim.policies.base import Policy
from sim.process import Process

# Shared operating point for every unsupervised detector: the fraction of clean
# training windows it flags. Training data is legitimate by construction, so this
# is a false-positive budget, not an expected attack rate.
CONTAM = 0.01

# Label convention for supervised policies.
NORMAL, HOG, MONITOR = 0, 1, 2


# ---- unsupervised detector wrappers (uniform: fit(X) / outlier_mask(X)) ------

class PredictOutlier:
    """For sklearn detectors whose predict() returns +1 inlier / -1 outlier."""

    def __init__(self, make: Callable):
        self.make = make
        self.scaler = StandardScaler()
        self.model = None

    def fit(self, X: np.ndarray) -> None:
        self.model = self.make()
        self.model.fit(self.scaler.fit_transform(X))

    def outlier_mask(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(self.scaler.transform(X)) == -1


class GmmOutlier:
    def __init__(
        self,
        n_components: int = 1,
        covariance_type: str = "diag",
        contamination: float = CONTAM,
    ):
        self.contam = contamination
        self.scaler = StandardScaler()
        self.gmm = GaussianMixture(
            n_components=n_components, covariance_type=covariance_type, random_state=0
        )
        self.thr = 0.0

    def fit(self, X: np.ndarray) -> None:
        Xs = self.scaler.fit_transform(X)
        self.gmm.fit(Xs)
        self.thr = float(np.quantile(self.gmm.score_samples(Xs), self.contam))

    def outlier_mask(self, X: np.ndarray) -> np.ndarray:
        return self.gmm.score_samples(self.scaler.transform(X)) < self.thr


class KnnOutlier:
    def __init__(self, k: int = 200, contamination: float = CONTAM):
        self.k = k
        self.contam = contamination
        self.scaler = StandardScaler()
        self.nn = None
        self.thr = 0.0

    def fit(self, X: np.ndarray) -> None:
        Xs = self.scaler.fit_transform(X)
        k = min(self.k, len(Xs) - 1)
        self.nn = NearestNeighbors(n_neighbors=k, n_jobs=1).fit(Xs)
        # kneighbors() with no X excludes each training point from its own
        # neighbors, so the threshold matches what an unseen point will score.
        kd = self.nn.kneighbors()[0][:, -1]
        self.thr = float(np.quantile(kd, 1.0 - self.contam))

    def outlier_mask(self, X: np.ndarray) -> np.ndarray:
        kd = self.nn.kneighbors(self.scaler.transform(X))[0][:, -1]
        return kd > self.thr


class HbosOutlier:
    """Histogram-based outlier score: cheap, per-feature density."""

    def __init__(self, bins: int = 6, contamination: float = CONTAM):
        self.bins = bins
        self.contam = contamination
        self.scaler = StandardScaler()
        self.edges: list[np.ndarray] = []
        self.logdens: list[np.ndarray] = []
        self.thr = 0.0

    def _score(self, Xs: np.ndarray) -> np.ndarray:
        s = np.zeros(len(Xs))
        for j in range(Xs.shape[1]):
            idx = np.clip(np.digitize(Xs[:, j], self.edges[j][1:-1]), 0, self.bins - 1)
            s += -self.logdens[j][idx]
        return s

    def fit(self, X: np.ndarray) -> None:
        Xs = self.scaler.fit_transform(X)
        self.edges, self.logdens = [], []
        for j in range(Xs.shape[1]):
            hist, edges = np.histogram(Xs[:, j], bins=self.bins, density=True)
            self.edges.append(edges)
            self.logdens.append(np.log(np.clip(hist, 1e-6, None)))
        self.thr = float(np.quantile(self._score(Xs), 1.0 - self.contam))

    def outlier_mask(self, X: np.ndarray) -> np.ndarray:
        return self._score(self.scaler.transform(X)) > self.thr


# ---- supervised classifier wrapper ------------------------------------------

class ClfWrap:
    def __init__(self, make: Callable):
        self.make = make
        self.scaler = StandardScaler()
        self.clf = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        self.clf = self.make()
        self.clf.fit(self.scaler.fit_transform(X), y)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.clf.predict(self.scaler.transform(X))


# ---- the policy that wraps any model ----------------------------------------

class MLPolicy(Policy):
    def __init__(
        self,
        name: str,
        group: str,
        kind: str,  # "unsupervised" | "supervised"
        builder: Callable,
        penalty: float = 0.1,
        boost: float = 2.0,
        requires_torch: bool = False,
    ):
        self.name = name
        self.group = group
        self.kind = kind
        self.builder = builder
        self.penalty = penalty
        self.boost = boost
        self.requires_torch = requires_torch
        self.model = None

    def fit(self, legit_features: np.ndarray, labels: np.ndarray | None = None) -> None:
        self.model = self.builder()
        if self.kind == "unsupervised":
            self.model.fit(legit_features)
        else:
            if labels is None:
                raise ValueError(f"{self.name}: supervised policy needs labels")
            self.model.fit(legit_features, labels)

    def multipliers(self, processes: list[Process], obs: np.ndarray) -> np.ndarray:
        m = np.ones(len(processes), dtype=float)
        if self.kind == "unsupervised":
            m[self.model.outlier_mask(obs)] = self.penalty
        else:
            pred = self.model.predict(obs)
            m[pred == HOG] = self.penalty
            m[pred == MONITOR] = self.boost
        return m


def _autoencoder_builder():
    """Optional torch autoencoder. Imported lazily so CPU machines don't need torch."""
    import torch  # noqa: F401  (import error here is caught by the sweep runner)

    from sim.policies.autoencoder import TorchAutoencoderOutlier

    return TorchAutoencoderOutlier(contamination=CONTAM)


# ---- the ~15 augmented schedulers, grouped --------------------------------
#
# Hyperparameters are calibrated on held-out LEGITIMATE behavior (benign apps
# never seen in training, plus the monitor) and the naive hog only; the mimicry
# attacker is never used to choose them. See docs/architecture.md.

def unsupervised_policies() -> list[MLPolicy]:
    return [
        MLPolicy("iforest", "ml-unsupervised", "unsupervised",
                 lambda: PredictOutlier(lambda: IsolationForest(contamination=CONTAM, random_state=0, n_jobs=1))),
        MLPolicy("ocsvm", "ml-unsupervised", "unsupervised",
                 lambda: PredictOutlier(lambda: OneClassSVM(nu=CONTAM, gamma=0.01))),
        # k stays below the smallest legitimate cluster (train_samples windows of
        # one process) so the monitor's own cluster is never scored as an outlier.
        MLPolicy("lof", "ml-unsupervised", "unsupervised",
                 lambda: PredictOutlier(lambda: LocalOutlierFactor(
                     n_neighbors=200, contamination=CONTAM, novelty=True, n_jobs=1))),
        MLPolicy("elliptic", "ml-unsupervised", "unsupervised",
                 lambda: PredictOutlier(lambda: EllipticEnvelope(contamination=CONTAM, random_state=0))),
        MLPolicy("knn", "ml-unsupervised", "unsupervised", KnnOutlier),
        MLPolicy("hbos", "ml-unsupervised", "unsupervised", HbosOutlier),
        MLPolicy("gmm", "ml-unsupervised", "unsupervised", GmmOutlier),
        MLPolicy("autoencoder", "ml-unsupervised", "unsupervised",
                 _autoencoder_builder, requires_torch=True),
    ]


def supervised_policies() -> list[MLPolicy]:
    return [
        MLPolicy("rf", "ml-supervised", "supervised",
                 lambda: ClfWrap(lambda: RandomForestClassifier(n_estimators=120, random_state=0, n_jobs=1))),
        MLPolicy("histgb", "ml-supervised", "supervised",
                 lambda: ClfWrap(lambda: HistGradientBoostingClassifier(random_state=0))),
        MLPolicy("logreg", "ml-supervised", "supervised",
                 lambda: ClfWrap(lambda: LogisticRegression(max_iter=500))),
        MLPolicy("svm_rbf", "ml-supervised", "supervised",
                 lambda: ClfWrap(lambda: SVC(kernel="rbf", C=1.0, gamma="scale"))),
        MLPolicy("mlp", "ml-supervised", "supervised",
                 lambda: ClfWrap(lambda: MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=800, random_state=0))),
        MLPolicy("knn_clf", "ml-supervised", "supervised",
                 lambda: ClfWrap(lambda: KNeighborsClassifier(n_neighbors=7, n_jobs=1))),
        MLPolicy("naive_bayes", "ml-supervised", "supervised",
                 lambda: ClfWrap(GaussianNB)),
    ]
