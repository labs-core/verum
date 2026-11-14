#!/usr/bin/env python3
"""
Build libverum.a and the benchmark ELF with the TriCore GCC toolchain.

Benchmark images live under ``build/tricore``; release archives use the shared ``release`` layout.

    build/tricore/<opt>/<config>/bench.elf         linked QEMU benchmark image
    build/tricore/<opt>/<config>/bench.map

Examples:
    python benchmark/arch/tricore/build.py --config ad_direct_unrolled --opt O0
    python benchmark/arch/tricore/build.py --opt O0        # whole matrix
    python benchmark/arch/tricore/build.py --print-flags  # flags for an ADS project
"""

import argparse
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from toolchain import (  # noqa: E402
    Toolchain, run, REPO_ROOT, BUILD_ROOT, BENCH_DIR, CONFIGS, ASCON_SOURCES,
    BENCH_SOURCES, BENCH_INCLUDES, INCLUDES, ALL_HEADERS, compute_sha256, needs_rebuild,
)
from scripts._common import ASCON_COMPOUNDS, BASE_OPT_FLAGS, FLAGS_CMAKE_PATH

QEMU_DEFS = ["-DVERUM_TRICORE_QEMU_DEF"]
LINK_SCRIPT = os.path.join(BENCH_DIR, "link.ld")
BOARD_SOURCES = [
    os.path.join(BENCH_DIR, "crt0.S"),
    os.path.join(BENCH_DIR, "startup.c"),
    os.path.join(BENCH_DIR, "output.c"),
]


def opt_tag(opt):
    return opt.lstrip("-")


def gcc_include_flags(tc, includes):
    return ["-I" + tc.path(flag[2:]) for flag in includes]


def select_configs(cfg_filter="all", fips_mode=None, include_preinterleaved=False):
    selected = []
    for name, defs in CONFIGS:
        if cfg_filter not in (None, "all") and name != cfg_filter:
            continue
        # Pre-interleaving only affects AEAD, so the "all" matrix skips it (same rule as the Clang benchmark).
        if cfg_filter in (None, "all") and "preinterleaved" in name and not include_preinterleaved:
            continue
        is_fips = name.startswith("fips_")
        if fips_mode is True and not is_fips:
            continue
        if fips_mode is False and is_fips:
            continue
        selected.append((name, defs))
    return selected


def config_dir(opt, cfg_name, build_root=None):
    return os.path.join(build_root or BUILD_ROOT, opt_tag(opt), cfg_name)


def build_release_config(tc, cfg_name, defs, out_base_dir, force=False, opt_flag=None):
    """Build TriCore release archives and stack data into the standard release layout."""
    arch_folder = "tricore"
    ascon_arch_dir = os.path.join(out_base_dir, "ascon", cfg_name, arch_folder)
    verum_arch_dir = os.path.join(out_base_dir, "verum", cfg_name, arch_folder)
    ascon_su_dir = os.path.join(out_base_dir, "ascon", cfg_name, "stack_usage", arch_folder)
    verum_su_dir = os.path.join(out_base_dir, "verum", cfg_name, "stack_usage", arch_folder)
    os.makedirs(ascon_arch_dir, exist_ok=True)
    os.makedirs(verum_arch_dir, exist_ok=True)

    verum_archive = os.path.join(verum_arch_dir, "libverum.a")
    compound_archives = {
        name: os.path.join(ascon_arch_dir, f"{name}.a") for name in ASCON_COMPOUNDS
    }
    targets = [verum_archive] + list(compound_archives.values())
    deps = ASCON_SOURCES + ALL_HEADERS + [
        FLAGS_CMAKE_PATH, __file__, os.path.join(HERE, "toolchain.py")]
    if not force and not opt_flag and all(not needs_rebuild(target, deps) for target in targets):
        digest = compute_sha256(verum_archive)
        print(f"    [=] Up-to-date: verum/{cfg_name}/{arch_folder}/libverum.a ({digest[:16]}...)")
        return verum_archive, digest

    temp_dir = os.path.join(BUILD_ROOT, "release_obj", cfg_name)
    os.makedirs(temp_dir, exist_ok=True)
    opt_flags = [opt_flag] if opt_flag else BASE_OPT_FLAGS
    warnings, options, _ = tc.project_flags()
    obj_map = {}
    for src in ASCON_SOURCES:
        obj_path = os.path.join(temp_dir, os.path.splitext(os.path.basename(src))[0] + ".o")
        run([tc.tool("gcc")] + tc.compiler_flags +
            ["-c", tc.path(src), "-o", tc.path(obj_path)] + tc.arch_flags + opt_flags +
            warnings + options + defs + gcc_include_flags(tc, INCLUDES))
        obj_map[src] = obj_path

    for comp_name, comp_sources in ASCON_COMPOUNDS.items():
        archive = compound_archives[comp_name]
        if os.path.exists(archive):
            os.remove(archive)
        objects = [tc.path(obj_map[src]) for src in comp_sources if src in obj_map]
        run([tc.tool("ar"), "rcs", tc.path(archive)] + objects)
        run([tc.tool("strip"), "-g", tc.path(archive)])

    if os.path.exists(verum_archive):
        os.remove(verum_archive)
    run([tc.tool("ar"), "rcs", tc.path(verum_archive)] + [tc.path(obj) for obj in obj_map.values()])
    run([tc.tool("strip"), "-g", tc.path(verum_archive)])
    shutil.copy2(verum_archive, os.path.join(out_base_dir, "verum", cfg_name,
                                             f"libverum_{arch_folder}.a"))

    os.makedirs(ascon_su_dir, exist_ok=True)
    os.makedirs(verum_su_dir, exist_ok=True)
    for filename in os.listdir(temp_dir):
        if filename.endswith(".su"):
            shutil.copy2(os.path.join(temp_dir, filename), os.path.join(ascon_su_dir, filename))
            shutil.copy2(os.path.join(temp_dir, filename), os.path.join(verum_su_dir, filename))
    shutil.rmtree(temp_dir, ignore_errors=True)

    digest = compute_sha256(verum_archive)
    print(f"    [+] Built: verum/{cfg_name}/{arch_folder}/libverum.a ({digest[:16]}...)")
    return verum_archive, digest


def build_library(tc, cfg_name, defs, opt, force=False, verbose=True):
    """Compile ASCON_SOURCES with the project flags (translated to GCC) into libverum.a."""
    out = config_dir(opt, cfg_name)
    obj_dir = os.path.join(out, "obj")
    os.makedirs(obj_dir, exist_ok=True)
    lib = os.path.join(out, "libverum.a")

    deps = ASCON_SOURCES + ALL_HEADERS
    if not force and not needs_rebuild(lib, deps):
        if verbose:
            print(f"    [=] Up-to-date: {opt_tag(opt)}/{cfg_name}/libverum.a")
        return lib

    warnings, options, _ = tc.project_flags()
    objs = []
    for src in ASCON_SOURCES:
        obj = os.path.join(obj_dir, os.path.splitext(os.path.basename(src))[0] + ".o")
        run([tc.tool("gcc")] + tc.compiler_flags +
            ["-c", tc.path(src), "-o", tc.path(obj)] + tc.arch_flags +
            [opt] + warnings + options + defs + gcc_include_flags(tc, INCLUDES))
        objs.append(obj)

    if os.path.exists(lib):
        os.remove(lib)
    run([tc.tool("ar"), "rcs", tc.path(lib)] + [tc.path(obj) for obj in objs])
    if verbose:
        print(f"    [+] Built:  {opt_tag(opt)}/{cfg_name}/libverum.a ({compute_sha256(lib)[:16]}...)")
    return lib


def build_bench(tc, cfg_name, defs, opt, lib, force=False, build_root=None):
    """Compile the shared benchmark sources + TriCore board files and link bench.elf."""
    out = config_dir(opt, cfg_name, build_root)
    obj_dir = os.path.join(out, "bench_obj")
    os.makedirs(obj_dir, exist_ok=True)
    elf = os.path.join(out, "bench.elf")
    mapfile = os.path.join(out, "bench.map")

    sources = list(BENCH_SOURCES) + BOARD_SOURCES
    if not force and not needs_rebuild(elf, sources + [lib, LINK_SCRIPT, os.path.join(BENCH_DIR, "harness", "perf.h")] + ALL_HEADERS):
        return elf

    # The shared benchmark sources do #include "harness/perf.h", which resolves relative to the
    # including file and therefore finds the Clang harness. Force-including the TriCore perf.h first
    # claims the shared include guard (VERUM_BENCH_PERF_H_), so the shared header becomes a no-op.
    includes = ["-I" + tc.path(BENCH_DIR)] + gcc_include_flags(tc, BENCH_INCLUDES) + [
        "-include", tc.path(os.path.join(BENCH_DIR, "harness", "perf.h"))]
    warnings, options, _ = tc.project_flags()
    objs = []
    for src in sources:
        stem, ext = os.path.splitext(os.path.basename(src))
        obj = os.path.join(obj_dir, f"{stem}{ext.lstrip('.').lower()}.o")
        if ext == ".S":
            run([tc.tool("gcc")] + tc.compiler_flags +
                ["-c", tc.path(src), "-o", tc.path(obj)] + tc.arch_flags + [opt])
        else:
            run([tc.tool("gcc")] + tc.compiler_flags +
                ["-c", tc.path(src), "-o", tc.path(obj)] + tc.arch_flags +
                [opt] + warnings + options + defs + QEMU_DEFS + includes)
        objs.append(obj)

    run([tc.tool("gcc")] + tc.compiler_flags + tc.arch_flags +
        [opt, "-nostartfiles", f"-Wl,-T,{tc.path(LINK_SCRIPT)}", "-Wl,--gc-sections",
         f"-Wl,-Map,{tc.path(mapfile)}", "-o", tc.path(elf)] +
        [tc.path(obj) for obj in objs] + [tc.path(lib), tc.gcc_runtime])
    return elf


def print_flags(tc, opt):
    warnings, options, dropped = tc.project_flags()
    print(f"# Toolchain : {tc.version}")
    print(f"# Home      : {tc.home}")
    print(f"# CPU       : -mcpu={tc.cpu} (TC1.6.2)")
    print("\n## Architecture flags\n" + " ".join(tc.arch_flags))
    print("\n## Optimisation\n" + opt)
    print("\n## Project compile options (release/flags.cmake)\n" + " ".join(options))
    print("\n## Project warnings (release/flags.cmake, GCC-translated)\n" + " ".join(warnings))
    print("\n## Include paths\n" + " ".join(INCLUDES))
    print("\n## Clang-only flags with no GCC equivalent (dropped)\n" + " ".join(dropped))


def parse_opts(text):
    return ["-" + o.lstrip("-") for o in text.split(",") if o.strip()]


def add_common_args(parser):
    parser.add_argument("--toolchain", default=None,
                        help="tricore-gcc install dir (default: $TRICORE_GCC_HOME or the AURIX Configuration Studio path)")
    parser.add_argument("--cpu", default=None, help="GCC -mcpu family name (default: tc39xx, i.e. TC1.6.2)")
    parser.add_argument("--config", default="all", help="Configuration name or 'all' (default: all)")
    parser.add_argument("--fips", action="store_true", help="Only FIPS 140-3 configurations")
    parser.add_argument("--no-fips", action="store_true", help="Only non-FIPS configurations")
    parser.add_argument("--opt", type=parse_opts, default=["-O0"], metavar="LIST",
                        help="Comma separated optimisation levels, e.g. O0,O2 or -O0 (default: O0, as in release/flags.cmake)")
    parser.add_argument("--force", action="store_true", help="Rebuild even if up to date")


def fips_mode_from(args):
    if args.fips and not args.no_fips:
        return True
    if args.no_fips and not args.fips:
        return False
    return None


def make_toolchain(args):
    from toolchain import DEFAULT_CPU
    return Toolchain(home=args.toolchain, cpu=args.cpu or DEFAULT_CPU)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_args(parser)
    parser.add_argument("--print-flags", action="store_true", help="Print the resolved GCC flag set and exit")
    args = parser.parse_args()

    tc = make_toolchain(args)
    print(f"[*] {tc.version}  (-mcpu={tc.cpu})")

    if args.print_flags:
        print_flags(tc, args.opt[0])
        return 0

    _, _, dropped = tc.project_flags()
    if dropped:
        print(f"[i] {len(dropped)} clang-only flag(s) have no GCC equivalent and were dropped "
              f"(see --print-flags): {' '.join(dropped)}")

    configs = select_configs(args.config, fips_mode_from(args))
    for opt in args.opt:
        print(f"[*] TriCore GCC build, {opt}, {len(configs)} configuration(s)")
        for name, defs in configs:
            lib = build_library(tc, name, defs, opt, force=args.force)
            elf = build_bench(tc, name, defs, opt, lib, force=args.force)
            print(f"        image: {os.path.relpath(elf, REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

