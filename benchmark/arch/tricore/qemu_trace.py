#!/usr/bin/env python3
"""
Run a TriCore benchmark image in QEMU and reconstruct cycle / instruction counts.

QEMU does not model the TC1.6.2 CCNT/ICNT counters. Instead, with VERUM_TRICORE_QEMU_DEF the guest
perf_cycles_read() / perf_insn_read() emit a marker store to 0xF2000000, and this script runs QEMU
single-stepped with an execution log (-accel tcg,one-insn-per-tb=on -d exec,nochain), counting executed instructions
between markers. This is the same model the ARM (SysTick under -icount shift=0) and RISC-V
(mcycle/minstret under -icount) runs use: one instruction = one cycle (1 IPC), so cycles == insns
here, apart from the few marker instructions themselves. It says nothing about TriCore pipeline
timing; use silicon / the AURIX simulator for that.

Output: the guest transcript with the cycles=/insns= fields of every BENCH: line replaced by the
measured values. Designed to run inside WSL / Linux next to qemu-system-tricore.

    python3 qemu_trace.py <bench.elf> [--qemu "qemu-system-tricore -M ..."]
"""

import argparse
import re
import subprocess
import sys

QEMU_DEFAULT = "qemu-system-tricore -M tricore_testboard -cpu tc37x -nographic -monitor none"
CHAR_RE = re.compile(r"Invalid write at addr 0x[Ff]10000([0-9A-Fa-f]{2})")
MARK_RE = re.compile(r"Invalid write at addr 0x[Ff]2000000")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--qemu", default=QEMU_DEFAULT)
    args = ap.parse_args()

    cmd = args.qemu.split() + ["-accel", "tcg,one-insn-per-tb=on", "-d", "exec,nochain,invalid_mem",
                               "-D", "/dev/stdout", "-kernel", args.elf]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20)

    executed = 0
    marks = []          # executed-instruction count at each marker, reset after every BENCH line
    line_chars = []
    out = sys.stdout

    for raw in proc.stdout:
        if raw.startswith("Trace"):
            executed += 1
            continue
        c = CHAR_RE.search(raw)
        if c:
            ch = chr(int(c.group(1), 16))
            if ch == "\n":
                text = "".join(line_chars)
                line_chars = []
                if text.startswith("BENCH:") and len(marks) >= 4:
                    t_start, i_start, i_stop, t_stop = marks[-4:]
                    text = re.sub(r"cycles=\d+", f"cycles={t_stop - t_start}", text)
                    text = re.sub(r"insns=\d+", f"insns={i_stop - i_start}", text)
                    marks = []
                out.write(text + "\n")
            else:
                line_chars.append(ch)
            continue
        if MARK_RE.search(raw):
            marks.append(executed)

    proc.wait()
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
