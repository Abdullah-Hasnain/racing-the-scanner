"""The aggregator separates hiding (PROT_NONE<->RW) from JIT (RW<->RX) flips (#14).

Events mirror Tracee v0.24's `security_file_mprotect`: `prot` is the requested
protection and `prev_prot` is the region's vm_flags, so it carries VM_MAY* bits
(0x10, 0x20, 0x40) above the R/W/X bits.
"""

import json

from detection.aggregator import aggregate

VM_MAY = 0x70  # VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC, set on ordinary anonymous memory


def mprotect_event(pid: int, prev_prot, prot, comm: str = "proc") -> str:
    return json.dumps({
        "processId": pid,
        "processName": comm,
        "eventName": "security_file_mprotect",
        "args": [
            {"name": "pathname", "value": ""},
            {"name": "prot", "value": prot},
            {"name": "ctime", "value": 0},
            {"name": "prev_prot", "value": prev_prot},
            {"name": "addr", "value": "0x7f0000000000"},
            {"name": "len", "value": 4096},
        ],
    })


def features(lines: list[str]) -> dict[int, dict]:
    return {pid: w.as_features() for pid, w in aggregate(lines).items()}


def test_hider_lock_and_unlock_count_as_none_rw_flips():
    lines = [
        mprotect_event(7, VM_MAY | 0x3, 0x0),  # lock: RW -> NONE
        mprotect_event(7, VM_MAY, 0x3),        # unlock: NONE -> RW
    ]
    f = features(lines)[7]
    assert f["none_rw_flips"] == 2
    assert f["rw_rx_flips"] == 0


def test_jit_exec_and_write_flips_count_as_rw_rx_flips():
    lines = [
        mprotect_event(9, VM_MAY | 0x3, 0x5),  # RW -> RX: code emitted, now run it
        mprotect_event(9, VM_MAY | 0x5, 0x3),  # RX -> RW: patch it again
    ]
    f = features(lines)[9]
    assert f["rw_rx_flips"] == 2
    assert f["none_rw_flips"] == 0


def test_parsed_string_prots_classify_like_raw_ints():
    # With `--output option:parse-arguments`, Tracee renders prot as flag names.
    # A PROT_NONE region's prev_prot is vm_flags 0x70, which has no PROT_* bit,
    # so it renders as "" rather than "PROT_NONE".
    lines = [
        mprotect_event(7, "", "PROT_READ|PROT_WRITE"),               # hider unlock
        mprotect_event(7, "PROT_READ|PROT_WRITE", "PROT_NONE"),      # hider lock
        mprotect_event(9, "PROT_READ|PROT_WRITE", "PROT_READ|PROT_EXEC"),  # JIT
    ]
    f = features(lines)
    assert (f[7]["none_rw_flips"], f[7]["rw_rx_flips"]) == (2, 0)
    assert (f[9]["none_rw_flips"], f[9]["rw_rx_flips"]) == (0, 1)


def test_raw_mprotect_syscall_counts_but_never_flips():
    # The mprotect syscall event has no prev_prot, so it cannot show a transition.
    line = json.dumps({
        "processId": 7,
        "processName": "v2",
        "eventName": "mprotect",
        "args": [
            {"name": "addr", "value": "0x7f0000000000"},
            {"name": "len", "value": 4096},
            {"name": "prot", "value": 3},
        ],
    })
    f = features([line])[7]
    assert f["n_mprotect"] == 1
    assert (f["none_rw_flips"], f["rw_rx_flips"]) == (0, 0)


def test_any_flip_to_or_from_prot_none_counts_as_hiding():
    # A hider gains nothing by unlocking with exec or read-only access instead of RW.
    lines = [
        mprotect_event(7, VM_MAY, 0x7),        # NONE -> RWX
        mprotect_event(7, VM_MAY | 0x5, 0x0),  # RX -> NONE
        mprotect_event(7, VM_MAY, 0x1),        # NONE -> R
    ]
    f = features(lines)[7]
    assert (f["none_rw_flips"], f["rw_rx_flips"]) == (3, 0)


def syscall_event(pid: int, name: str, **args) -> str:
    return json.dumps({
        "processId": pid,
        "processName": "v2",
        "eventName": name,
        "args": [{"name": k, "value": v} for k, v in args.items()],
    })


def test_segv_handler_installs_and_signal_returns_are_counted():
    lines = [
        syscall_event(7, "rt_sigaction", signum=11, act="0x7ffd0000", oldact="0x0"),
        syscall_event(7, "rt_sigaction", signum=14, act="0x7ffd0000", oldact="0x0"),  # SIGALRM
        syscall_event(7, "rt_sigaction", signum=11, act="0x0", oldact="0x7ffd0000"),  # query only
        *[syscall_event(7, "rt_sigreturn") for _ in range(3)],
    ]
    f = features(lines)[7]
    assert f["segv_handlers"] == 1
    assert f["n_rt_sigreturn"] == 3
    assert "sigsegv" not in f
