#!/usr/bin/env python3
"""Small comparative benchmark: launch overhead and compute-heavy shell loop.
Run after building: ABWRAP_BIN=build/abwrap python3 benchmarks/bench.py
"""
import os, statistics, subprocess, time

AB = os.environ.get("ABWRAP_BIN", "build/abwrap")
BASE = []
for p in ["/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib", "/usr/lib64"]:
    if os.path.exists(p): BASE += ["--ro-bind", p, p]


def measure(cmd, n=30):
    vals=[]
    for _ in range(n):
        t=time.perf_counter_ns()
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        vals.append((time.perf_counter_ns()-t)/1e6)
    return statistics.median(vals), statistics.quantiles(vals, n=20)[18]

native = ["/bin/true"]
sandbox = [AB] + BASE + ["--", "/bin/true"]
for name, cmd in [("native launch", native), ("abwrap launch", sandbox)]:
    med,p95=measure(cmd)
    print(f"{name:16s} median={med:8.3f} ms  p95={p95:8.3f} ms")

native_compute=["/bin/sh","-c","i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done"]
sandbox_compute=[AB]+BASE+["--"]+native_compute
for name, cmd in [("native compute",native_compute),("abwrap compute",sandbox_compute)]:
    med,p95=measure(cmd,5)
    print(f"{name:16s} median={med:8.3f} ms  p95={p95:8.3f} ms")
