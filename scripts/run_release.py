#!/usr/bin/env python3
"""Convenience entry point for scripts/release/run_release.py"""
import os
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
RELEASE_SCRIPT = os.path.join(SCRIPTS_DIR, "release", "run_release.py")

if __name__ == "__main__":
    import subprocess
    sys.exit(subprocess.call([sys.executable, RELEASE_SCRIPT] + sys.argv[1:]))
