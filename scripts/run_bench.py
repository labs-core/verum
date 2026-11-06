#!/usr/bin/env python3
"""Convenience entry point for scripts/benchmark/run_bench.py"""
import os
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
BENCH_SCRIPT = os.path.join(SCRIPTS_DIR, "benchmark", "run_bench.py")

if __name__ == "__main__":
    import subprocess
    sys.exit(subprocess.call([sys.executable, BENCH_SCRIPT] + sys.argv[1:]))
