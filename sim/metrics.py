"""Detection ROC-AUC and the spread of metrics across runs.

The scheduling metrics (latency, miss rate, monitor share) live in
SimResult.summary(). This module adds two things on top:

- detection_auc: how well a policy's continuous score ranks the attacker above
  legitimate processes. It is threshold-free, so it shows what the detector can
  see, not only what the scheduler did with it.
- aggregate: median of every metric across the --runs repeats, plus the
  interquartile range (q25, q75) of the key ones.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

# Metrics whose spread across runs is reported next to the median.
SPREAD = ("p95_latency", "miss_rate", "roc_auc", "roc_auc_benign")


def detection_auc(scores: np.ndarray | None, roles: np.ndarray, versus: tuple[str, ...]) -> float:
    """ROC-AUC of a hog score: attacker windows positive, windows of `versus` roles negative.

    Values are reported raw: below 0.5 means the detector scores the attacker as
    MORE normal than the negatives. NaN when the policy has no detector (scores
    is None) or one class is absent (e.g. the "none" condition has no attacker).
    """
    if scores is None:
        return float("nan")
    pos = roles == "attacker"
    keep = pos | np.isin(roles, versus)
    if not pos.any() or pos[keep].all():
        return float("nan")
    return float(roc_auc_score(pos[keep], scores[keep]))


def aggregate(df: pd.DataFrame, keys: list[str]) -> pd.DataFrame:
    """Median of every numeric column per group, with `<metric>_q25` and
    `<metric>_q75` (the interquartile range across runs) after each metric in
    SPREAD. NaN metrics (AUC without a detector) stay NaN."""
    g = df.groupby(keys, sort=False)
    agg = g[list(df.select_dtypes("number").columns)].median()
    cols: list[str] = []
    for c in agg.columns:
        cols.append(c)
        if c in SPREAD:
            agg[f"{c}_q25"] = g[c].quantile(0.25)
            agg[f"{c}_q75"] = g[c].quantile(0.75)
            cols += [f"{c}_q25", f"{c}_q75"]
    return agg[cols].reset_index()
