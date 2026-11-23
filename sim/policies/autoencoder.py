"""Optional torch autoencoder outlier detector (one of the 15 augmented schedulers).

This module imports torch at import time, so it is only imported lazily by the
builder in ml.py. On a machine without torch the policy is skipped by the sweep
runner. Install torch from requirements-gpu.txt to enable it.

Interface matches the other unsupervised detectors: fit(X) / outlier_mask(X).
"""

from __future__ import annotations

import numpy as np
import torch
from sklearn.preprocessing import StandardScaler
from torch import nn


class _AE(nn.Module):
    def __init__(self, n_in: int, hidden: int = 8, latent: int = 3):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(n_in, hidden), nn.ReLU(), nn.Linear(hidden, latent))
        self.dec = nn.Sequential(nn.Linear(latent, hidden), nn.ReLU(), nn.Linear(hidden, n_in))

    def forward(self, x):
        return self.dec(self.enc(x))


class TorchAutoencoderOutlier:
    def __init__(
        self,
        epochs: int = 60,
        contamination: float = 0.01,
        lr: float = 1e-2,
        hidden: int = 8,
        latent: int = 3,
    ):
        self.epochs = epochs
        self.contam = contamination
        self.lr = lr
        self.hidden = hidden
        self.latent = latent
        self.scaler = StandardScaler()
        self.net: _AE | None = None
        self.thr = 0.0
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

    def _recon_err(self, Xs: np.ndarray) -> np.ndarray:
        self.net.eval()
        with torch.no_grad():
            t = torch.tensor(Xs, dtype=torch.float32, device=self.device)
            out = self.net(t)
            return ((out - t) ** 2).mean(dim=1).cpu().numpy()

    def fit(self, X: np.ndarray) -> None:
        Xs = self.scaler.fit_transform(X).astype(np.float32)
        torch.manual_seed(0)  # weight init is the only randomness; fix it like random_state=0
        self.net = _AE(Xs.shape[1], hidden=self.hidden, latent=self.latent).to(self.device)
        opt = torch.optim.Adam(self.net.parameters(), lr=self.lr)
        loss_fn = nn.MSELoss()
        t = torch.tensor(Xs, device=self.device)
        self.net.train()
        for _ in range(self.epochs):
            opt.zero_grad()
            loss = loss_fn(self.net(t), t)
            loss.backward()
            opt.step()
        self.thr = float(np.quantile(self._recon_err(Xs), 1.0 - self.contam))

    def outlier_mask(self, X: np.ndarray) -> np.ndarray:
        Xs = self.scaler.transform(X).astype(np.float32)
        return self._recon_err(Xs) > self.thr
