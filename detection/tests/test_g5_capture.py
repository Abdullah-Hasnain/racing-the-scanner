"""A G5 batch scores the deepest process under each launcher, once (#13)."""

from detection.g5_capture import harness_args, scored_pids

# label,pid,comm rows as a batch records them: each launcher's tree, parent first.
BATCH = [
    {"label": "benign:go-gc", "pid": "10", "comm": "python"},
    {"label": "benign:go-gc", "pid": "11", "comm": "go"},
    {"label": "benign:go-gc", "pid": "12", "comm": "gcstress"},
    {"label": "benign:sqlite", "pid": "20", "comm": "python"},
    {"label": "attacker:v2", "pid": "30", "comm": "v2"},
    {"label": "attacker:v3", "pid": "40", "comm": "v3"},
]


def test_scored_pids_take_the_deepest_process_per_label():
    attackers, benign = scored_pids(BATCH)
    assert attackers == {"v2": 30, "v3": 40}
    assert benign == {"go-gc": 12, "sqlite": 20}  # the go toolchain is not scored


def test_harness_args_label_every_scored_pid():
    args = harness_args(BATCH)
    a, b = args.index("--attacker-pid"), args.index("--benign-pid")
    assert sorted(args[a + 1:b]) == ["30", "40"]
    assert sorted(args[b + 1:]) == ["12", "20"]


def test_chain_to_hand_back_covers_every_dir_up_to_the_root_it_was_made_under(tmp_path):
    # capture runs as root and may create results/, results/g5/ and the run dir;
    # all of them must go back to the user, or the unprivileged score step can't write.
    from detection.g5_capture import chain_below

    run_dir = tmp_path / "results" / "g5" / "20261124-000000"
    assert chain_below(run_dir, tmp_path) == [run_dir, run_dir.parent, run_dir.parent.parent]
    assert chain_below(tmp_path / "x.json", tmp_path) == [tmp_path / "x.json"]
    elsewhere = tmp_path.parent / "elsewhere.json"  # a --log outside the user's home
    assert chain_below(elsewhere, tmp_path) == [elsewhere]


# A recorded batch as the capture sees it at +15 s, with every launcher running.
GOOD = [
    {"label": "benign:node", "pid": "10", "comm": "python"},
    {"label": "benign:node", "pid": "11", "comm": "node"},
    {"label": "benign:sqlite", "pid": "20", "comm": "python3"},
    {"label": "attacker:v3", "pid": "40", "comm": "v3"},
]
RUNNING = {"benign:node": None, "benign:sqlite": None, "attacker:v3": None}


def test_a_full_running_batch_has_no_problems():
    from detection.g5_capture import batch_problems

    assert batch_problems(GOOD, RUNNING) == []


def test_a_launcher_that_exited_stops_the_capture_instead_of_being_scored():
    # run_benign.py exits 1 when node isn't on pkexec's PATH; its tree is then just
    # the launcher, which scored_pids would otherwise score as benign:node.
    from detection.g5_capture import batch_problems

    dead = [{"label": "benign:node", "pid": "10", "comm": "python"}, *GOOD[2:]]
    problems = batch_problems(dead, {**RUNNING, "benign:node": 1})
    assert problems == ["benign:node exited with code 1 before the batch was recorded"]


def test_a_deepest_process_that_is_not_the_workload_is_a_problem():
    # e.g. still inside the go toolchain at +15 s: the toolchain would be scored as the GC
    from detection.g5_capture import batch_problems

    rows = [{"label": "benign:go-gc", "pid": "10", "comm": "python"},
            {"label": "benign:go-gc", "pid": "11", "comm": "go"}]
    assert batch_problems(rows, {"benign:go-gc": None}) == [
        "benign:go-gc: deepest process is 'go', expected 'gcstress'"]


def test_score_skips_batches_already_in_detection_g5(tmp_path, monkeypatch):
    # Re-running score (after a crash, or --no-llm then with the LLM) must not append
    # duplicate default_sigs/custom rows, which G5 sums.
    import json
    import subprocess

    from detection import g5_capture

    run_dir = tmp_path / "20261125-000000"
    run_dir.mkdir()
    (run_dir / "capture.json").write_text(json.dumps({"tracee_log": "/abs/g5.json", "batches": 2}))
    for i in range(2):
        (run_dir / f"batch_{i}.csv").write_text("label,pid,comm\nattacker:v3,40,v3\nbenign:sqlite,20,python\n")
    res = tmp_path / "results"
    res.mkdir()
    (res / "detection_g5.csv").write_text("run_id,detector\n20261125-000000-batch_0,custom\n")
    monkeypatch.setenv("RTS_RESULTS_DIR", str(res))
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: calls.append((cmd, kw)))

    g5_capture.main(["score", str(run_dir)])

    assert len(calls) == 1
    cmd, kw = calls[0]
    assert cmd[cmd.index("--run-id") + 1] == "20261125-000000-batch_1"
    assert kw["cwd"] == g5_capture.REPO  # -m detection.harness needs the repo root


def test_module_imports_without_posix_only_modules():
    # Windows has no pwd; make test must still collect this file there (scripts/setup.ps1).
    import subprocess
    import sys

    r = subprocess.run([sys.executable, "-c",
                        "import sys; sys.modules['pwd'] = None\nimport detection.g5_capture"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
