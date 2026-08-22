#!/usr/bin/env python3
import errno
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

AB = os.environ["ABWRAP_BIN"]
RAW = os.environ["RAW_OPEN_BIN"]
OPENAT = os.environ["OPENAT_PROBE_BIN"]
FS_PROBE = os.environ["FS_PROBE_BIN"]


def runtime_binds():
    args = []
    for p in ["/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib", "/usr/lib64"]:
        if os.path.exists(p):
            args += ["--ro-bind", p, p]
    return args


def run_ab(extra, command, check=False):
    cmd = [AB] + runtime_binds() + extra + ["--"] + command
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


class AbwrapIntegration(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def test_hidden_unbound_path(self):
        cp = run_ab([], ["/bin/cat", "/etc/passwd"])
        self.assertNotEqual(cp.returncode, 0)

    def test_ro_bind_denies_shell_write(self):
        p = self.root / "a.txt"
        p.write_text("orig\n")
        cp = run_ab(["--ro-bind", str(self.root), "/work"],
                    ["/bin/sh", "-c", "printf bad > /work/a.txt"])
        self.assertNotEqual(cp.returncode, 0)
        self.assertEqual(p.read_text(), "orig\n")
        self.assertIn("Read-only file system", cp.stderr)

    def test_ro_bind_denies_direct_syscall(self):
        p = self.root / "a.txt"
        p.write_text("orig\n")
        cp = run_ab(["--ro-bind", str(self.root), "/work", "--ro-bind", RAW, "/raw_open"],
                    ["/raw_open", "write", "/work/a.txt"])
        self.assertEqual(cp.returncode, errno.EROFS)
        self.assertEqual(p.read_text(), "orig\n")

    def test_rw_bind_allows_write(self):
        p = self.root / "a.txt"
        p.write_text("orig\n")
        cp = run_ab(["--bind", str(self.root), "/work"],
                    ["/bin/sh", "-c", "printf good > /work/a.txt"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(p.read_text(), "good")

    def test_ro_mutations_denied(self):
        p = self.root / "a.txt"
        p.write_text("orig")
        script = "rm /work/a.txt || true; chmod 777 /work/a.txt || true; mv /work/a.txt /work/b.txt || true"
        cp = run_ab(["--ro-bind", str(self.root), "/work"], ["/bin/sh", "-c", script])
        self.assertEqual(cp.returncode, 0)
        self.assertTrue(p.exists())
        self.assertFalse((self.root / "b.txt").exists())

    def test_mountpoint_cannot_be_removed(self):
        cp = run_ab(["--bind", str(self.root), "/work"], ["/bin/rmdir", "/work"])
        self.assertNotEqual(cp.returncode, 0)
        self.assertTrue(self.root.exists())

    def test_virtual_absolute_symlink(self):
        src = self.root / "src"
        dst = self.root / "dst"
        src.mkdir(); dst.mkdir()
        (dst / "value").write_text("virtual-target")
        os.symlink("/dst/value", src / "link")
        cp = run_ab(["--ro-bind", str(src), "/src", "--ro-bind", str(dst), "/dst"],
                    ["/bin/cat", "/src/link"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout, "virtual-target")

    def test_absolute_symlink_cannot_escape_visible_tree(self):
        src = self.root / "src"
        src.mkdir()
        os.symlink("/etc/passwd", src / "escape")
        cp = run_ab(["--ro-bind", str(src), "/src"], ["/bin/cat", "/src/escape"])
        self.assertNotEqual(cp.returncode, 0)

    def test_getcwd_is_virtualized(self):
        (self.root / "sub").mkdir()
        cp = run_ab(["--bind", str(self.root), "/work", "--chdir", "/work/sub"], ["/bin/pwd"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout.strip(), "/work/sub")

    def test_env_and_clearenv(self):
        cp = run_ab(["--clearenv", "--setenv", "PATH", "/bin:/usr/bin", "--setenv", "ABW_X", "ok"],
                    ["/bin/sh", "-c", "printf '%s' \"$ABW_X\""])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout, "ok")

    def test_tmpfs_compat_ephemeral_dir(self):
        cp = run_ab(["--tmpfs", "/tmp"], ["/bin/sh", "-c", "echo x >/tmp/a && cat /tmp/a"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout.strip(), "x")

    def test_ptrace_fallback_backend(self):
        p = self.root / "a.txt"
        p.write_text("orig")
        cp = run_ab(["--backend", "ptrace", "--ro-bind", str(self.root), "/work"],
                    ["/bin/sh", "-c", "printf bad > /work/a.txt"])
        self.assertNotEqual(cp.returncode, 0)
        self.assertEqual(p.read_text(), "orig")

    def test_child_exec_keeps_policy(self):
        p = self.root / "a.txt"
        p.write_text("orig")
        cp = run_ab(["--ro-bind", str(self.root), "/work", "--ro-bind", RAW, "/raw_open"],
                    ["/bin/sh", "-c", "/raw_open write /work/a.txt"])
        self.assertEqual(cp.returncode, errno.EROFS)
        self.assertEqual(p.read_text(), "orig")


    def test_ro_directory_can_be_listed(self):
        (self.root / "x").write_text("ok")
        cp = run_ab(["--ro-bind", str(self.root), "/work"], ["/bin/ls", "/work"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("x", cp.stdout.splitlines())


    def test_root_bind_can_be_listed_rw(self):
        cp = subprocess.run([AB, "--bind", "/", "/", "--", "/bin/ls", "/"],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("bin", cp.stdout.splitlines())

    def test_root_bind_can_be_listed_ro(self):
        cp = subprocess.run([AB, "--ro-bind", "/", "/", "--", "/bin/ls", "/"],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("bin", cp.stdout.splitlines())

    def test_python_rw_bind_writes_bytecode_cache(self):
        py = pathlib.Path(os.sys.executable)
        prefix = py.parent.parent
        mod = self.root / "mymod.py"
        mod.write_text("value = 42\n")
        args = runtime_binds() + ["--ro-bind", str(prefix), str(prefix),
                                  "--bind", str(self.root), "/work",
                                  "--setenv", "PYTHONPATH", "/work"]
        cp = subprocess.run([AB] + args + ["--", str(py), "-c",
                            "import mymod; print(mymod.value)"],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout.strip(), "42")
        caches = list((self.root / "__pycache__").glob("mymod*.pyc"))
        self.assertTrue(caches, "RW bind must allow Python bytecode cache creation")

    def test_python_ro_bind_imports_without_bytecode_cache(self):
        py = pathlib.Path(os.sys.executable)
        prefix = py.parent.parent
        mod = self.root / "mymod.py"
        mod.write_text("value = 42\n")
        args = runtime_binds() + ["--ro-bind", str(prefix), str(prefix),
                                  "--ro-bind", str(self.root), "/work",
                                  "--setenv", "PYTHONPATH", "/work"]
        cp = subprocess.run([AB] + args + ["--", str(py), "-c",
                            "import mymod; print(mymod.value)"],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout.strip(), "42")
        self.assertFalse((self.root / "__pycache__").exists())

    def test_proc_root_hides_unrelated_host_pids(self):
        cp = run_ab(["--proc", "/proc"], ["/bin/ls", "/proc"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertNotIn(str(os.getpid()), cp.stdout.splitlines())
        self.assertIn("self", cp.stdout.splitlines())
        self.assertIn("cpuinfo", cp.stdout.splitlines())

    def test_proc_self_magic_links_are_virtual(self):
        (self.root / "sub").mkdir()
        cp = run_ab(["--proc", "/proc", "--bind", str(self.root), "/work", "--chdir", "/work/sub"],
                    ["/bin/sh", "-c", "readlink /proc/self/root; readlink /proc/self/cwd; readlink /proc/self/exe"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        lines = cp.stdout.splitlines()
        self.assertEqual(lines[0], "/")
        # readlink runs in its own child process but inherits the virtual cwd.
        self.assertEqual(lines[1], "/work/sub")
        self.assertTrue(lines[2].startswith("/bin/") or lines[2].startswith("/usr/bin/"), lines[2])

    def test_proc_root_magic_link_cannot_escape(self):
        cp = run_ab(["--proc", "/proc"], ["/bin/cat", "/proc/self/root/etc/passwd"])
        self.assertNotEqual(cp.returncode, 0)

    def test_proc_visible_root_magic_link_respects_bind(self):
        p = self.root / "value"
        p.write_text("inside")
        cp = run_ab(["--proc", "/proc", "--ro-bind", str(self.root), "/work"],
                    ["/bin/cat", "/proc/self/root/work/value"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout, "inside")

    def test_proc_openat_dirfd_keeps_virtual_semantics(self):
        cp = run_ab(["--proc", "/proc", "--ro-bind", OPENAT, "/openat_probe"],
                    ["/openat_probe", "/proc/self", "status"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Name:", cp.stdout)

    def test_proc_openat_root_escape_denied(self):
        cp = run_ab(["--proc", "/proc", "--ro-bind", OPENAT, "/openat_probe"],
                    ["/openat_probe", "/proc/self", "root/etc/passwd"])
        self.assertNotEqual(cp.returncode, 0)

    def test_proc_mount_views_do_not_leak_host_bind_source(self):
        cp = run_ab(["--proc", "/proc", "--ro-bind", str(self.root), "/work"],
                    ["/bin/cat", "/proc/self/mountinfo"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn(" /work ", cp.stdout)
        self.assertNotIn(str(self.root), cp.stdout)

    def test_proc_maps_rewrites_host_paths(self):
        tool = self.root / "tool"
        shutil.copy2("/bin/cat", tool)
        tool.chmod(0o755)
        cp = run_ab(["--proc", "/proc", "--ro-bind", str(tool), "/tool"],
                    ["/tool", "/proc/self/maps"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("/tool", cp.stdout)
        self.assertNotIn(str(self.root), cp.stdout)
        self.assertNotIn("/internal/procgen/", cp.stdout)

    def test_proc_fd_hidden_inherited_file_cannot_be_reopened(self):
        hidden = self.root / "hidden"
        hidden.write_text("secret")
        with hidden.open("r") as inp:
            cmd = [AB] + runtime_binds() + ["--proc", "/proc", "--", "/bin/cat", "/proc/self/fd/0"]
            cp = subprocess.run(cmd, stdin=inp, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(cp.returncode, 0)
        self.assertNotIn("secret", cp.stdout)

    def test_proc_fd_visible_file_reopens_and_readlink_is_virtual(self):
        p = self.root / "a.txt"
        p.write_text("hello")
        cp = run_ab(["--proc", "/proc", "--ro-bind", str(self.root), "/work"],
                    ["/bin/sh", "-c", "exec 3</work/a.txt; readlink /proc/self/fd/3; cat /proc/self/fd/3"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        lines = cp.stdout.splitlines()
        self.assertEqual(lines[0], "/work/a.txt")
        self.assertEqual(lines[1], "hello")

    def test_proc_fd_write_to_ro_bind_is_denied(self):
        p = self.root / "a.txt"
        p.write_text("orig")
        cp = run_ab(["--proc", "/proc", "--ro-bind", str(self.root), "/work", "--ro-bind", RAW, "/raw_open"],
                    ["/bin/sh", "-c", "exec 3</work/a.txt; /raw_open write /proc/self/fd/3"])
        self.assertEqual(cp.returncode, errno.EROFS)
        self.assertEqual(p.read_text(), "orig")

    def test_proc_fd_stdout_reopen_remains_compatible(self):
        cp = run_ab(["--proc", "/proc"], ["/bin/sh", "-c", "printf ok >/proc/self/fd/1"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout, "ok")

    def test_proc_write_is_read_only(self):
        cp = run_ab(["--proc", "/proc"], ["/bin/sh", "-c", "printf x >/proc/sys/kernel/hostname"])
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("Read-only file system", cp.stderr)

    def test_internal_backing_tree_not_visible(self):
        cp = run_ab(["--proc", "/proc", "--tmpfs", "/tmp"], ["/bin/ls", "-a", "/"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        names = set(cp.stdout.splitlines())
        self.assertNotIn("internal", names)
        self.assertNotIn(".abwrap-internal", names)
        self.assertNotIn(".ephemeral", names)

    def test_proc_ptrace_backend(self):
        cp = run_ab(["--backend", "ptrace", "--proc", "/proc"], ["/bin/sh", "-c", "head -1 /proc/self/status"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertTrue(cp.stdout.startswith("Name:"), cp.stdout)


    def test_proc_status_hides_supervisor_tracer_pid(self):
        cp = run_ab(["--proc", "/proc"], ["/bin/sh", "-c", "grep '^TracerPid:' /proc/self/status"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout.strip().split()[-1], "0")

    def test_proc_generated_fd_does_not_expose_internal_backing(self):
        cp = run_ab(["--ro-bind", "/", "/", "--proc", "/proc"],
                    ["/bin/sh", "-c", "exec 3</proc/self/maps; readlink /proc/self/fd/3"])
        self.assertNotEqual(cp.returncode, 0)
        self.assertNotIn("abwrap.", cp.stdout + cp.stderr)
        self.assertNotIn("/internal/", cp.stdout + cp.stderr)

    def test_proc_can_live_at_nonstandard_destination(self):
        cp = run_ab(["--proc", "/p"], ["/bin/sh", "-c", "head -1 /p/self/status"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertTrue(cp.stdout.startswith("Name:"), cp.stdout)

    def test_root_bind_auto_virtualizes_proc_self_fd(self):
        # Regression from Termux/Android: generic symlink resolution of /proc/self
        # used the supervisor PID, making linker readlink(/proc/self/fd/N) fail.
        cp = run_ab(["--ro-bind", "/", "/"],
                    ["/bin/sh", "-c", "exec 3</etc/hosts; readlink /proc/self/fd/3"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertTrue(cp.stdout.strip().endswith("/etc/hosts"), cp.stdout)

    def test_ro_root_keeps_dev_null_writable(self):
        # A read-only mount blocks filesystem mutation, not I/O to an existing
        # character device. Shells and runtimes routinely redirect to /dev/null.
        cp = run_ab(["--ro-bind", "/", "/"],
                    ["/bin/sh", "-c", "printf ok >/dev/null; printf pass"])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stdout, "pass")


    def test_ro_bind_denies_xattr_mutation(self):
        p = self.root / "a.txt"
        p.write_text("orig")
        cp = run_ab(["--ro-bind", str(self.root), "/work", "--ro-bind", FS_PROBE, "/fs_probe"],
                    ["/fs_probe", "setxattr", "/work/a.txt"])
        self.assertEqual(cp.returncode, errno.EROFS, cp.stderr)

    def test_hidden_path_cannot_be_probed_with_getxattr(self):
        cp = run_ab(["--ro-bind", FS_PROBE, "/fs_probe"], ["/fs_probe", "getxattr", "/etc/passwd"])
        self.assertEqual(cp.returncode, errno.ENOENT, cp.stderr)

    def test_hidden_path_cannot_be_probed_with_statfs(self):
        cp = run_ab(["--ro-bind", FS_PROBE, "/fs_probe"], ["/fs_probe", "statfs", "/etc"])
        self.assertEqual(cp.returncode, errno.ENOENT, cp.stderr)

    def test_hidden_path_cannot_be_watched_with_inotify(self):
        cp = run_ab(["--ro-bind", FS_PROBE, "/fs_probe"], ["/fs_probe", "inotify", "/etc"])
        self.assertEqual(cp.returncode, errno.ENOENT, cp.stderr)

    def test_fallocate_on_ro_fd_is_denied(self):
        p = self.root / "a.txt"
        p.write_text("orig")
        cp = run_ab(["--ro-bind", str(self.root), "/work", "--ro-bind", FS_PROBE, "/fs_probe"],
                    ["/fs_probe", "fallocate", "/work/a.txt"])
        self.assertEqual(cp.returncode, errno.EROFS, cp.stderr)
        self.assertEqual(p.read_text(), "orig")

    def test_clone_untraced_escape_is_denied(self):
        cp = run_ab(["--ro-bind", FS_PROBE, "/fs_probe"], ["/fs_probe", "clone-untraced"])
        self.assertEqual(cp.returncode, errno.EPERM, cp.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
