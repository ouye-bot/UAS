# -*- coding: utf-8 -*-
"""SITL 持有进程诊断（一次性探针）：Popen 持有 wsl.exe，120s 时间线监视。"""
import subprocess
import sys
import time

p = subprocess.Popen(
    ["wsl", "bash", "-c",
     'exec bash -c \'~/ardupilot/build/sitl/bin/arducopter -S -w --model + --speedup 1 -I0 >/tmp/w.log 2>&1; echo "EXIT_RC=$? AT=$(date +%s.%N)" >> /tmp/death2.log\''],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
t0 = time.time()
while time.time() - t0 < 120:
    r = p.poll()
    alive = subprocess.run(
        ["wsl", "bash", "-c", "pgrep -f 'bin/arducopter' >/dev/null && echo A || echo D"],
        capture_output=True, text=True,
    ).stdout.strip()[-1]
    print(f"t={time.time()-t0:6.1f}s wsl_proc={'LIVE' if r is None else f'EXIT({r})'} sitl={alive}", flush=True)
    if r is not None and alive == "D":
        break
    time.sleep(10)
subprocess.run(["wsl", "bash", "-c", "cat /tmp/death2.log 2>/dev/null; tail -2 /tmp/w.log"], text=True)
p.kill()
