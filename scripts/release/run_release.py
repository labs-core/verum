#!/usr/bin/env python3
"""
Release Archive Builder for Verum.
Compiles, archives, and strips:
1. Modular compound libraries under release/ascon/<config>/<arch>/:
   - aead.a, hash.a, xof.a, cxof.a
2. Unified distribution library under release/verum/<config>/<arch>/:
   - libverum.a (consolidates all compounds) and libverum_<arch>.a alias

Skips rebuilding when sources are unchanged and prints the SHA-256 for each library.
"""

import os
import sys
import argparse
import subprocess
import shutil

# Add scripts directory to path to import _common
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from _common import (
    REPO_ROOT, RELEASE_DIR, ASCON_SOURCES, ASCON_COMPOUNDS, ALL_HEADERS, INCLUDES,
    FLAGS_CMAKE_PATH, PROJECT_WARNINGS, PROJECT_COMPILE_OPTIONS, BASE_OPT_FLAGS,
    CONFIGS, ARCH_SPECS, compute_sha256, needs_rebuild, get_verum_lib, get_compound_lib
)

def build_single_config(arch_key, cfg_name, defs, out_base_dir, force=False, opt_flag=None):
    spec = ARCH_SPECS[arch_key]
    
    # Target directories
    ascon_arch_dir = os.path.join(out_base_dir, "ascon", cfg_name, spec["folder"])
    ascon_su_dir = os.path.join(out_base_dir, "ascon", cfg_name, "stack_usage", arch_key)
    verum_arch_dir = os.path.join(out_base_dir, "verum", cfg_name, spec["folder"])
    verum_su_dir = os.path.join(out_base_dir, "verum", cfg_name, "stack_usage", arch_key)

    os.makedirs(ascon_arch_dir, exist_ok=True)
    os.makedirs(verum_arch_dir, exist_ok=True)

    verum_archive = os.path.join(verum_arch_dir, "libverum.a")
    verum_alias = os.path.join(out_base_dir, "verum", cfg_name, f"libverum_{arch_key}.a")

    compound_archives = {
        name: os.path.join(ascon_arch_dir, f"{name}.a")
        for name in ASCON_COMPOUNDS
    }

    all_targets = [verum_archive] + list(compound_archives.values())
    all_deps = ASCON_SOURCES + ALL_HEADERS + [FLAGS_CMAKE_PATH]

    # Check if all targets are up-to-date
    if not force and not opt_flag and all(not needs_rebuild(t, all_deps) for t in all_targets):
        v_sha = compute_sha256(verum_archive)
        print(f"    [=] Up-to-date: verum/{cfg_name}/{spec['folder']}/libverum.a (SHA-256: {v_sha[:16]}...)")
        return verum_archive, v_sha

    temp_dir = os.path.join(out_base_dir, ".tmp_build", arch_key, cfg_name)
    os.makedirs(temp_dir, exist_ok=True)

    opt_flags = [opt_flag] if opt_flag else BASE_OPT_FLAGS

    # 1. Compile each source object
    obj_map = {}
    for src in ASCON_SOURCES:
        base_name = os.path.splitext(os.path.basename(src))[0]
        obj_path = os.path.join(temp_dir, f"{base_name}.o")
        compile_cmd = [
            "clang",
            "-c", src,
            "-o", obj_path
        ] + spec["flags"] + opt_flags + PROJECT_WARNINGS + PROJECT_COMPILE_OPTIONS + defs + INCLUDES
        
        try:
            subprocess.check_output(compile_cmd, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Compilation failed for {src} in cfg {cfg_name} ({arch_key}):\n{e.output}")
            sys.exit(1)
        obj_map[src] = obj_path

    # 2. Build modular compound archives under release/ascon/<config>/<arch>/
    for comp_name, comp_sources in ASCON_COMPOUNDS.items():
        comp_ar = compound_archives[comp_name]
        if os.path.exists(comp_ar):
            os.remove(comp_ar)
        comp_objs = [obj_map[s] for s in comp_sources if s in obj_map]
        subprocess.check_call(["llvm-ar", "rcs", comp_ar] + comp_objs)
        subprocess.check_call(["llvm-strip", "-x", comp_ar])

    # 3. Build unified libverum.a under release/verum/<config>/<arch>/
    if os.path.exists(verum_archive):
        os.remove(verum_archive)
    all_objs = list(obj_map.values())
    subprocess.check_call(["llvm-ar", "rcs", verum_archive] + all_objs)
    subprocess.check_call(["llvm-strip", "-x", verum_archive])
    shutil.copy2(verum_archive, verum_alias)

    # 4. Preserve stack usage .su files in both hierarchy paths
    os.makedirs(ascon_su_dir, exist_ok=True)
    os.makedirs(verum_su_dir, exist_ok=True)
    for f in os.listdir(temp_dir):
        if f.endswith(".su"):
            shutil.copy2(os.path.join(temp_dir, f), os.path.join(ascon_su_dir, f))
            shutil.copy2(os.path.join(temp_dir, f), os.path.join(verum_su_dir, f))

    shutil.rmtree(temp_dir, ignore_errors=True)

    v_sha = compute_sha256(verum_archive)
    comp_shas = {name: compute_sha256(compound_archives[name])[:8] for name in ASCON_COMPOUNDS}
    comp_summary = " ".join(f"{k}:{v}" for k, v in comp_shas.items())
    print(f"    [+] Built: verum/{cfg_name}/{spec['folder']}/libverum.a ({v_sha[:16]}...) [{comp_summary}]")
    return verum_archive, v_sha

def build_arch(arch_key, out_base_dir, cfg_filter=None, fips_mode=None, force=False, opt_flag=None):
    print(f"[*] Checking/Building {arch_key} release libraries:")
    selected_configs = []
    for c in CONFIGS:
        if cfg_filter and cfg_filter != "all" and c[0] != cfg_filter:
            continue
        is_fips = c[0].startswith("fips_")
        if fips_mode is True and not is_fips:
            continue
        if fips_mode is False and is_fips:
            continue
        selected_configs.append(c)

    for cfg_name, defs in selected_configs:
        build_single_config(arch_key, cfg_name, defs, out_base_dir, force=force, opt_flag=opt_flag)
    print(f"[+] {arch_key} release check complete.\n")

def main():
    parser = argparse.ArgumentParser(description="Build and manage stripped release static archives.")
    parser.add_argument("--arch", choices=["x86_64", "arm", "riscv", "all"], default="all",
                        help="Target architecture (default: all)")
    parser.add_argument("--config", default="all",
                        help="Configuration name to build (default: all)")
    parser.add_argument("--fips", action="store_true", default=False,
                        help="Build only FIPS 140-3 configurations")
    parser.add_argument("--no-fips", action="store_true", default=False,
                        help="Build only non-FIPS configurations")
    parser.add_argument("--out-dir", default=RELEASE_DIR,
                        help="Output release directory")
    parser.add_argument("--opt", default=None,
                        help="Optional optimization flag override (default: -O0 from release/flags.cmake)")
    parser.add_argument("--force", action="store_true",
                        help="Force rebuild even if up to date")
    args = parser.parse_args()

    fips_mode = None
    if args.fips and not args.no_fips:
        fips_mode = True
    elif args.no_fips and not args.fips:
        fips_mode = False

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    targets = ["x86_64", "arm", "riscv"] if args.arch == "all" else [args.arch]
    for target in targets:
        build_arch(target, out_dir, cfg_filter=args.config, fips_mode=fips_mode, force=args.force, opt_flag=args.opt)

if __name__ == "__main__":
    main()
