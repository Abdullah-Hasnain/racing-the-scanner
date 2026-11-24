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
