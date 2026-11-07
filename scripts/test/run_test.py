#!/usr/bin/env python3
"""
Unit Test Runner for Verum.
Ensures x86_64 release static archives are built, prints the SHA-256 of the library under test,
compiles/links test runners (avoiding redundant rebuilds), and executes the Unity test suite.
"""

import os
import sys
import argparse
import subprocess

# Add scripts directory to path to import _common
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from _common import (
    REPO_ROOT, RELEASE_DIR, TEST_SOURCES, TEST_INCLUDES, ALL_HEADERS,
    PROJECT_WARNINGS, BASE_OPT_FLAGS, CONFIGS, compute_sha256, needs_rebuild, get_release_lib
)

# Also import run_release to build if missing
from release.run_release import build_single_config

def build_test_runner(cfg_name, defs, runner_bin_dir, force=False):
    os.makedirs(runner_bin_dir, exist_ok=True)
    lib_path = get_release_lib(cfg_name, "x86_64")
    
    # 1. Ensure release library exists and is up-to-date
    if force or not os.path.exists(lib_path):
        build_single_config("x86_64", cfg_name, defs, RELEASE_DIR, force=force)
    
    lib_sha = compute_sha256(lib_path)

    # 2. Compile and link test runner executable if needed
    runner_exe = os.path.join(runner_bin_dir, f"test_runner_{cfg_name}")
    if sys.platform.startswith("win"):
        runner_exe += ".exe"

    runner_deps = TEST_SOURCES + ALL_HEADERS + [lib_path]
    if force or needs_rebuild(runner_exe, runner_deps):
        compile_cmd = [
            "clang",
            "-O0",
            "-std=c11",
        ] + defs + TEST_INCLUDES + PROJECT_WARNINGS + TEST_SOURCES + [lib_path, "-o", runner_exe]

        try:
            subprocess.check_output(compile_cmd, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Compilation failed for test_runner_{cfg_name}:\n{e.output}")
            sys.exit(1)

    return runner_exe, lib_sha

def run_single_test(cfg_name, defs, runner_bin_dir, force=False):
    runner_exe, lib_sha = build_test_runner(cfg_name, defs, runner_bin_dir, force=force)

    print("=" * 80)
    print(f"CONFIGURATION : {cfg_name}")
    print(f"TARGET LIB    : release/verum/{cfg_name}/x86_64/libverum.a")
    print(f"LIB SHA-256   : {lib_sha}")
    print("-" * 80)

    try:
        proc = subprocess.run([runner_exe], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
        output = proc.stdout
        print(output.strip())
        passed = (proc.returncode == 0) and ("FAIL" not in output)
        print(f"STATUS        : {'PASSED' if passed else 'FAILED'}")
        return passed
    except subprocess.TimeoutExpired:
        print("[!] Execution timed out after 60s")
        return False
    except Exception as e:
        print(f"[!] Execution failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run unit test suite against release static archives.")
    parser.add_argument("--config", default="all",
                        help="Configuration name to test (default: all)")
    parser.add_argument("--fips", action="store_true", default=False,
                        help="Test only FIPS 140-3 configurations")
    parser.add_argument("--no-fips", action="store_true", default=False,
                        help="Test only non-FIPS configurations")
    parser.add_argument("--bin-dir", default=os.path.join(REPO_ROOT, "build", "test_bin"),
                        help="Directory to store compiled test runner executables")
    parser.add_argument("--force", action="store_true",
                        help="Force rebuild of libraries and test runners")
    args = parser.parse_args()

    bin_dir = os.path.abspath(args.bin_dir)
    os.makedirs(bin_dir, exist_ok=True)

    selected_configs = []
    for c in CONFIGS:
        if args.config != "all" and c[0] != args.config:
            continue
        is_fips = c[0].startswith("fips_")
        if args.fips and not args.no_fips and not is_fips:
            continue
        if args.no_fips and not args.fips and is_fips:
            continue
        selected_configs.append(c)
    
    results = {}
    for cfg_name, defs in selected_configs:
        success = run_single_test(cfg_name, defs, bin_dir, force=args.force)
        results[cfg_name] = success
        print()

    print("=" * 80)
    print("UNIT TEST MATRIX SUMMARY")
    print("=" * 80)
    total = len(results)
    passed_count = sum(1 for v in results.values() if v)
    for name, ok in results.items():
        status = "PASSED" if ok else "FAILED"
        print(f"  {name:<35} : {status}")
    print("-" * 80)
    print(f"Result: {passed_count}/{total} configurations passed.")
    print("=" * 80)

    if passed_count < total:
        sys.exit(1)

if __name__ == "__main__":
    main()
