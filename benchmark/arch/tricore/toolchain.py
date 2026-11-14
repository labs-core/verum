#!/usr/bin/env python3
"""
TriCore GCC (AURIX Development Studio / HighTec-derived) toolchain adapter.

This module is intentionally self-contained and independent from the Clang based
ARM / RISC-V / x86_64 pipeline in ``scripts/``. The only thing it shares with that
pipeline is the *data*: warnings, compile options, configuration matrix and source
lists are read through ``scripts/_common.py`` (which parses ``release/flags.cmake``),
so both pipelines always build the same library with the same flag intent.

Clang-only flags (``-Wshadow-all``, ``-Wcomma``, ``-ferror-limit=0``, ...) are
translated to their GCC equivalents or dropped. Dropped flags are reported and
cached, never silently ignored.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts._common import (  # noqa: E402
    PROJECT_WARNINGS,
    PROJECT_COMPILE_OPTIONS,
    CONFIGS,
    ASCON_SOURCES,
    BENCH_SOURCES,
    BENCH_INCLUDES,
    INCLUDES,
    ALL_HEADERS,
    compute_sha256,
    needs_rebuild,
)

# Default AURIX Configuration Studio installation; override with --toolchain or
# the TRICORE_GCC_HOME environment variable.
DEFAULT_TOOLCHAIN = r"C:\Infineon\AURIX-Configuration-Studio-1.0.24\eclipse\tricore-gcc11"
TOOLCHAIN_ENV = "TRICORE_GCC_HOME"
TOOL_PREFIX = "tricore-elf-"

# GCC has no -mcpu=tc37xx. TC37x is a TC1.6.2 core; the tc39xx family name selects
# TC1.6.2 (__TRICORE_CORE__ == 0x162) together with the family errata workarounds.
DEFAULT_CPU = "tc39xx"

BUILD_ROOT = os.path.join(REPO_ROOT, "build", "tricore")
BENCH_DIR = HERE

# Clang flag -> GCC equivalent. Everything else is probed against the real compiler.
FLAG_RENAMES = {
    "-Wshadow-all": "-Wshadow",
}

# Architecture flags: the TriCore counterpart of ARCH_SPECS[...]["flags"] in scripts/_common.py.
ARCH_FLAGS_TEMPLATE = [
    "-mcpu={cpu}",
    "-ffreestanding",
    "-nostdlib",
    "-ffunction-sections",
    "-fdata-sections",
    "-fstack-usage",
]


def _exe(name):
    return name + (".exe" if os.name == "nt" else "")


def _toolchain_home(home):
    if os.name != "nt" and len(home) > 2 and home[1] == ":":
        return f"/mnt/{home[0].lower()}/{home[2:].replace(chr(92), '/').lstrip('/')}"
    return home


def _windows_path(path):
    if path.startswith("/mnt/") and len(path) > 6 and path[5].isalpha() and path[6] == "/":
        return f"{path[5].upper()}:{path[6:]}"
    return path


class Toolchain:
    """Resolved TriCore GCC installation."""

    def __init__(self, home=None, cpu=DEFAULT_CPU):
        home = _toolchain_home(home or os.environ.get(TOOLCHAIN_ENV) or DEFAULT_TOOLCHAIN)
        self.home = os.path.abspath(home)
        self.cpu = cpu
        self.bin = os.path.join(self.home, "bin")
        self._windows_gcc = os.name != "nt" and self.tool("gcc").endswith(".exe")
        if not os.path.isfile(self.tool("gcc")):
            raise SystemExit(
                f"[!] tricore-elf-gcc not found in '{self.bin}'.\n"
                f"    Pass --toolchain <dir> or set {TOOLCHAIN_ENV} "
                f"(expected <dir>/bin/{_exe(TOOL_PREFIX + 'gcc')})."
            )
        self._version = None

    def tool(self, name):
        path = os.path.join(self.bin, TOOL_PREFIX + name)
        if os.name == "nt":
            return path + ".exe"
        if os.path.isfile(path):
            return path
        if os.path.isfile(path + ".exe"):
            return path + ".exe"
        return path

    def path(self, path):
        return _windows_path(os.fspath(path)) if self._windows_gcc else os.fspath(path)

    @property
    def version(self):
        if self._version is None:
            out = subprocess.check_output([self.tool("gcc"), "--version"], text=True)
            self._version = out.splitlines()[0].strip()
        return self._version

    @property
    def arch_flags(self):
        return [f.format(cpu=self.cpu) for f in ARCH_FLAGS_TEMPLATE]

    @property
    def compiler_flags(self):
        if not self._windows_gcc:
            return []
        libexec_root = os.path.join(self.home, "libexec", "gcc", "tricore-elf")
        versions = sorted(os.listdir(libexec_root))
        cc1_dir = os.path.join(libexec_root, versions[-1])
        assembler_dir = os.path.join(self.home, "tricore-elf", "bin")
        return ["-B", _windows_path(cc1_dir) + "/", "-B", _windows_path(assembler_dir) + "/"]

    @property
    def gcc_runtime(self):
        if not self._windows_gcc:
            return "-lgcc"
        lib_root = os.path.join(self.home, "lib", "gcc", "tricore-elf")
        versions = sorted(os.listdir(lib_root))
        return self.path(os.path.join(lib_root, versions[-1], "libgcc.a"))

    # ------------------------------------------------------------------ flags
    def _supported(self, flag):
        """A flag is supported if GCC accepts it for C without any diagnostic."""
        probe = subprocess.run(
            [self.tool("gcc")] + self.compiler_flags +
            [f"-mcpu={self.cpu}", flag, "-x", "c", "-fsyntax-only", "-"],
            input="int verum_probe;\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return probe.returncode == 0 and probe.stderr.strip() == ""

    def translate_flags(self, flags):
        """Translate clang-flavoured project flags to GCC. Returns (accepted, dropped)."""
        cache_path = os.path.join(BUILD_ROOT, ".flag-cache.json")
        key = f"{self.version}|{self.cpu}"
        cache = {}
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except (OSError, ValueError):
            cache = {}
        verdicts = cache.get(key, {})

        accepted, dropped = [], []
        for flag in flags:
            flag = FLAG_RENAMES.get(flag, flag)
            if flag not in verdicts:
                verdicts[flag] = self._supported(flag)
            (accepted if verdicts[flag] else dropped).append(flag)

        cache[key] = verdicts
        os.makedirs(BUILD_ROOT, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
        return accepted, dropped

    def project_flags(self):
        """(warnings, compile_options, dropped) in GCC form, derived from release/flags.cmake."""
        warns, dropped_w = self.translate_flags(PROJECT_WARNINGS)
        opts, dropped_o = self.translate_flags(PROJECT_COMPILE_OPTIONS)
        return warns, opts, dropped_w + dropped_o


def run(cmd, **kwargs):
    """Run a tool; on failure print its output and exit non-zero (build scripts only)."""
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **kwargs)
    if proc.returncode != 0:
        print(f"[!] Command failed ({proc.returncode}): {' '.join(cmd[:3])} ...")
        print(proc.stdout)
        raise SystemExit(1)
    return proc.stdout
