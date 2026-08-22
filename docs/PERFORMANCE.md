# Performance model

The fast backend traps only filesystem/sandbox-sensitive syscalls. This creates two regimes:

- **process-start / pathname / metadata-heavy code:** ptrace round trips are measurable;
- **CPU-heavy / ordinary read-write / futex-heavy code:** most syscalls remain native after startup.

## Reference sanity measurement

A development x86_64 Linux release build of v0.1 measured:

| workload | native median | abwrap median |
|---|---:|---:|
| `/bin/true` launch | 0.525 ms | 3.434 ms |
| ~272 ms shell integer loop | 271.785 ms | 271.223 ms |

These are not Android claims. v0.2 adds proc virtualization, but ordinary workloads that do not access generated proc nodes still use the same selective syscall fast path.

Run the benchmark on the actual target device:

```bash
ABWRAP_BIN=build/abwrap python3 benchmarks/bench.py
```

## Cost sources

A trapped pathname syscall can require:

1. ptrace stop/wakeup;
2. pathname read from tracee memory;
3. virtual bind/symlink/proc resolution;
4. pathname write into tracee scratch memory;
5. resume.

Denied calls, `getcwd/readlink` output translation, and emulated proc links can require an exit stop. `maps/smaps/status` access also creates a sanitized snapshot; these are intentionally slower than direct proc reads because correctness/path isolation is prioritized for those diagnostic interfaces.

## Optimization direction

If profiling shows interpreter/package-manager startup is dominated by repeated path metadata calls, the next useful optimization is a per-process path-resolution cache keyed by virtual cwd/dirfd origin, pathname, and policy generation, with invalidation on RW namespace mutations. Generated proc snapshots can also use short-lived per-process caching where freshness requirements permit it.
