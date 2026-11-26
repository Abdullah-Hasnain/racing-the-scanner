"""A policy that fails mid-sweep fails the command, unless --continue-on-error."""

from __future__ import annotations

import sys

import pytest

from sim import run_experiment as rx


@pytest.fixture
def sweep(tmp_path, monkeypatch):
    real = rx.run_policy

    def run_policy(name, cfg, runs):
        if name == "invariant":
            raise RuntimeError("boom")
        return real(name, cfg, runs=runs)

    monkeypatch.setattr(rx, "run_policy", run_policy)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["run_experiment", "--policies", "baseline", "invariant",
                                          "--runs", "1", "--smoke", "--out", str(tmp_path), *extra])
        return rx.main()

    return run


def test_a_failed_policy_exits_nonzero_and_names_it(sweep, capsys):
    assert sweep() == 1
    assert "invariant" in capsys.readouterr().err


def test_continue_on_error_keeps_the_exit_status_zero(sweep, tmp_path):
    assert sweep("--continue-on-error") == 0
    assert (tmp_path / "aggregate_mimicry.csv").exists()
