#!/usr/bin/env python3
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

rw = Path(os.environ["ABW_TEST_RW"])
ro = Path(os.environ["ABW_TEST_RO"])
tmp = Path(os.environ["ABW_TEST_TMP"])
bash = os.environ["ABW_TEST_BASH"]


def case_stdlib():
    # Common stdlib/shared-extension imports exercise Android's dynamic linker.
    assert hashlib.sha256(b"abwrap").hexdigest()
    import ssl  # noqa: F401
    import sqlite3  # noqa: F401
    print("python-case: stdlib PASS")


def case_fs():
    assert (ro / "input.txt").read_text() == "ro-input"
    assert "input.txt" in os.listdir(ro)
    assert any(e.name == "input.txt" for e in os.scandir(ro))
    assert any(p.name == "input.txt" for p in ro.iterdir())

    (rw / "py").mkdir(parents=True, exist_ok=True)
    p = rw / "py" / "data.txt"
    p.write_text("alpha\n")
    with p.open("a") as f:
        f.write("beta\n")
    assert p.read_text().splitlines() == ["alpha", "beta"]
    q = rw / "py" / "renamed.txt"
    os.replace(p, q)
    assert q.exists()
    link = rw / "py" / "link.txt"
    try:
        link.unlink()
    except FileNotFoundError:
        pass
    link.symlink_to("renamed.txt")
    assert link.read_text().endswith("beta\n")

    with tempfile.NamedTemporaryFile(dir=tmp, prefix="py-", delete=False) as f:
        f.write(b"tempdata")
        tname = f.name
    assert Path(tname).read_bytes() == b"tempdata"
    Path(tname).unlink()
    (rw / "py" / "data.json").write_text(json.dumps({"ok": True}))
    assert json.loads((rw / "py" / "data.json").read_text())["ok"] is True

    try:
        (ro / "python-write-test").write_text("bad")
    except OSError as e:
        assert e.errno in (errno.EROFS, errno.EACCES, errno.EPERM), e
    else:
        raise AssertionError("RO write unexpectedly succeeded")
    print("python-case: fs PASS")


def case_procfd():
    with (ro / "input.txt").open("rb") as f:
        proc_path = f"/proc/self/fd/{f.fileno()}"
        fd_link = os.readlink(proc_path)
        expected = str(ro / "input.txt")
        print(f"python-case: procfd link={fd_link!r} len={len(fd_link)} expected={expected!r} expected_len={len(expected)}")
        assert fd_link == expected, (fd_link, expected)
    print("python-case: procfd PASS")


def case_bytecode_rw():
    sys.path.insert(0, str(rw))
    (rw / "rwmod.py").write_text("VALUE = 123\n")
    importlib.invalidate_caches()
    sys.modules.pop("rwmod", None)
    rwmod = importlib.import_module("rwmod")
    assert rwmod.VALUE == 123
    rw_cache = rw / "__pycache__"
    assert rw_cache.is_dir() and any(
        x.name.startswith("rwmod") and x.suffix == ".pyc" for x in rw_cache.iterdir()
    )
    print("python-case: bytecode-rw PASS")


def case_bytecode_ro():
    sys.path.insert(0, str(ro))
    importlib.invalidate_caches()
    sys.modules.pop("romod", None)
    romod = importlib.import_module("romod")
    assert romod.VALUE == 456
    assert not (ro / "__pycache__").exists()
    print("python-case: bytecode-ro PASS")


def case_subprocess():
    cp = subprocess.run(
        [bash, "-c", "printf python-subprocess-ok"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert cp.stdout == "python-subprocess-ok"

    code = "from pathlib import Path; print(Path('/proc/self/exe').resolve())"
    cp = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert cp.stdout.strip()
    print("python-case: subprocess PASS")


CASES = {
    "stdlib": case_stdlib,
    "fs": case_fs,
    "procfd": case_procfd,
    "bytecode-rw": case_bytecode_rw,
    "bytecode-ro": case_bytecode_ro,
    "subprocess": case_subprocess,
}


def main():
    requested = sys.argv[1:] or ["all"]
    if requested == ["all"]:
        requested = ["stdlib", "fs", "procfd", "bytecode-rw", "bytecode-ro", "subprocess"]
    for name in requested:
        fn = CASES.get(name)
        if fn is None:
            raise SystemExit(f"unknown case: {name}; choices: all {' '.join(CASES)}")
        print(f"python-case: {name} start")
        fn()
    print("python-workload: PASS")


if __name__ == "__main__":
    main()
