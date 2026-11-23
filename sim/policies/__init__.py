"""Policy registry. `build_policy(name)` returns a fresh, untrained policy.

Names:
  baseline                               -> S0 control (stock scheduler)
  invariant                              -> S3 hard CPU-reservation floor
  iforest ocsvm lof elliptic knn hbos gmm autoencoder   -> unsupervised augmented
  rf histgb logreg svm_rbf mlp knn_clf naive_bayes      -> supervised augmented

"all" in the runner expands to baseline + every augmented policy + invariant
(torch-only policies are skipped automatically when torch is not installed).
"""

from __future__ import annotations

from sim.policies.base import BaselinePolicy, InvariantPolicy, Policy
from sim.policies.ml import supervised_policies, unsupervised_policies

_BASE = {"baseline": BaselinePolicy, "invariant": InvariantPolicy}


def _ml_index() -> dict[str, Policy]:
    return {p.name: p for p in (*unsupervised_policies(), *supervised_policies())}


def build_policy(name: str) -> Policy:
    if name in _BASE:
        return _BASE[name]()
    idx = _ml_index()
    if name in idx:
        return idx[name]
    raise KeyError(f"unknown policy '{name}'. Known: {', '.join(all_policies())}")


def augmented_policies() -> list[str]:
    return [p.name for p in (*unsupervised_policies(), *supervised_policies())]


def all_policies() -> list[str]:
    return ["baseline", *augmented_policies(), "invariant"]


def expand(names: list[str], include_torch: bool = True) -> list[str]:
    """Resolve CLI policy selectors (supports 'all')."""
    out: list[str] = []
    for n in names:
        out.extend(all_policies() if n == "all" else [n])
    if not include_torch:
        idx = _ml_index()
        out = [n for n in out if not (n in idx and idx[n].requires_torch)]
    # de-dup, preserve order
    seen: set[str] = set()
    return [n for n in out if not (n in seen or seen.add(n))]
