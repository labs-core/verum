#!/usr/bin/env python3
"""Convenience entry point for scripts/test/run_test.py"""
import os
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_SCRIPT = os.path.join(SCRIPTS_DIR, "test", "run_test.py")

if __name__ == "__main__":
    import subprocess
    sys.exit(subprocess.call([sys.executable, TEST_SCRIPT] + sys.argv[1:]))
