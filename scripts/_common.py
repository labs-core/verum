#!/usr/bin/env python3
"""
Common configuration, flags, paths, and utilities shared across:
- scripts/release/run_release.py
- scripts/test/run_test.py
- scripts/benchmark/run_bench.py
"""

import os
import sys
import re
import hashlib
import glob
from pathlib import Path

# Paths
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RELEASE_DIR = os.path.join(REPO_ROOT, "release")
ASCON_RELEASE_DIR = os.path.join(RELEASE_DIR, "ascon")
VERUM_RELEASE_DIR = os.path.join(RELEASE_DIR, "verum")
FLAGS_CMAKE_PATH = os.path.join(RELEASE_DIR, "flags.cmake")

# Canonical Library Sources
ASCON_SOURCES = [
    os.path.join(REPO_ROOT, "source", "ascon", "aead.c"),
    os.path.join(REPO_ROOT, "source", "ascon", "ascon.c"),
    os.path.join(REPO_ROOT, "source", "ascon", "cxof.c"),
    os.path.join(REPO_ROOT, "source", "ascon", "hash.c"),
    os.path.join(REPO_ROOT, "source", "ascon", "xof.c"),
    os.path.join(REPO_ROOT, "source", "auxiliary", "memory.c"),
]

# Modular Ascon Compound Source Mapping
ASCON_COMPOUNDS = {
    "aead": [
        os.path.join(REPO_ROOT, "source", "ascon", "aead.c"),
        os.path.join(REPO_ROOT, "source", "ascon", "ascon.c"),
        os.path.join(REPO_ROOT, "source", "auxiliary", "memory.c"),
    ],
    "hash": [
        os.path.join(REPO_ROOT, "source", "ascon", "hash.c"),
        os.path.join(REPO_ROOT, "source", "ascon", "ascon.c"),
        os.path.join(REPO_ROOT, "source", "auxiliary", "memory.c"),
    ],
    "xof": [
        os.path.join(REPO_ROOT, "source", "ascon", "xof.c"),
        os.path.join(REPO_ROOT, "source", "ascon", "ascon.c"),
        os.path.join(REPO_ROOT, "source", "auxiliary", "memory.c"),
    ],
    "cxof": [
        os.path.join(REPO_ROOT, "source", "ascon", "cxof.c"),
        os.path.join(REPO_ROOT, "source", "ascon", "ascon.c"),
        os.path.join(REPO_ROOT, "source", "auxiliary", "memory.c"),
    ],
}

# Canonical Header Include Paths
INCLUDES = [
    "-I" + os.path.join(REPO_ROOT, "include"),
    "-I" + os.path.join(REPO_ROOT, "source", "ascon"),
]

# All Header Files for Rebuild Detection
ALL_HEADERS = (
    glob.glob(os.path.join(REPO_ROOT, "include", "**", "*.h"), recursive=True) +
    glob.glob(os.path.join(REPO_ROOT, "source", "**", "*.h"), recursive=True)
)

# Test Harness Sources
TEST_SOURCES = [
    os.path.join(REPO_ROOT, "test", "runner.c"),
    os.path.join(REPO_ROOT, "test", "unity", "unity.c"),
    os.path.join(REPO_ROOT, "test", "suite", "ascon", "aead.c"),
    os.path.join(REPO_ROOT, "test", "suite", "ascon", "hash.c"),
    os.path.join(REPO_ROOT, "test", "suite", "ascon", "xof.c"),
    os.path.join(REPO_ROOT, "test", "suite", "ascon", "cxof.c"),
    os.path.join(REPO_ROOT, "test", "suite", "ascon", "fips.c"),
]

TEST_INCLUDES = INCLUDES + [
    "-I" + os.path.join(REPO_ROOT, "test", "unity"),
    "-I" + os.path.join(REPO_ROOT, "test", "suite", "ascon"),
]

# Benchmark Harness Sources
BENCH_SOURCES = [
    os.path.join(REPO_ROOT, "benchmark", "runner.c"),
    os.path.join(REPO_ROOT, "benchmark", "suite", "ascon", "bench_ascon.c"),
]

BENCH_INCLUDES = INCLUDES + [
    "-I" + os.path.join(REPO_ROOT, "benchmark"),
]

# Load Unified Compilation Flags and Configurations directly from release/flags.cmake
def _parse_flags_cmake(path):
    if not os.path.isfile(path):
        return {}, []
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    matches = re.findall(r"set\s*\(\s*([A-Za-z0-9_]+)\s+([^)]+)\)", content, re.DOTALL)
    raw = {k: v.split() for k, v in matches}

    cfg_names = raw.get("MATRIX_CONFIG_NAMES", [])
    configs = []
    for cfg in cfg_names:
        defs = raw.get(f"DEFS_{cfg}", [])
        configs.append((cfg, defs))
    return raw, configs

_RAW_FLAGS, CONFIGS = _parse_flags_cmake(FLAGS_CMAKE_PATH)
PROJECT_WARNINGS = _RAW_FLAGS.get("PROJECT_WARNINGS", [])
PROJECT_COMPILE_OPTIONS = _RAW_FLAGS.get("PROJECT_COMPILE_OPTIONS", [])
BASE_OPT_FLAGS = _RAW_FLAGS.get("PROJECT_BASE_FLAGS", ["-O0"])

# Architecture Target Flags
ARCH_SPECS = {
    "x86_64": {
        "folder": "x86_64",
        "flags": ["-ffunction-sections", "-fstack-usage"]
    },
    "arm": {
        "folder": "arm",
        "flags": [
            "--target=armv7em-none-eabi",
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=soft",
            "-ffreestanding",
            "-nostdlib",
            "-ffunction-sections",
            "-fstack-usage"
        ]
    },
    "riscv": {
        "folder": "riscv",
        "flags": [
            "--target=riscv32-unknown-elf",
            "-march=rv32imac_zicsr",
            "-mabi=ilp32",
            "-mcmodel=medany",
            "-ffreestanding",
            "-nostdlib",
            "-ffunction-sections",
            "-fstack-usage"
        ]
    }
}

def compute_sha256(filepath):
    """Compute the SHA-256 hash of a file."""
    if not os.path.isfile(filepath):
        return "<file not found>"
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def needs_rebuild(target_file, source_files):
    """
    Check if target_file is missing or older than any of the source_files.
    Avoids rebuilding libraries and executables when sources are unchanged.
    """
    if not os.path.exists(target_file):
        return True
    try:
        target_mtime = os.path.getmtime(target_file)
        for s in source_files:
            if os.path.exists(s) and os.path.getmtime(s) > target_mtime:
                return True
    except OSError:
        return True
    return False

def get_verum_lib(cfg_name, arch_key):
    """Return the absolute path to a consolidated libverum.a under release/verum/<cfg>/<arch>/libverum.a."""
    return os.path.join(VERUM_RELEASE_DIR, cfg_name, arch_key, "libverum.a")

def get_compound_lib(cfg_name, arch_key, compound_name, primitive="ascon"):
    """Return the absolute path to a compound static archive (e.g. release/ascon/<cfg>/<arch>/aead.a)."""
    return os.path.join(RELEASE_DIR, primitive, cfg_name, arch_key, f"{compound_name}.a")

def get_release_lib(cfg_name, arch_key, primitive="verum"):
    """Return the primary library path for testing/benchmarking (defaults to release/verum/<cfg>/<arch>/libverum.a)."""
    if primitive == "verum":
        return get_verum_lib(cfg_name, arch_key)
    return os.path.join(RELEASE_DIR, primitive, cfg_name, arch_key, "libverum.a")
