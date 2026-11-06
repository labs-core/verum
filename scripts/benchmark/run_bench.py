#!/usr/bin/env python3
"""
Bare-metal QEMU benchmark driver for ARMv7E-M and RISC-V 32 RV32IMAC.
Links against stripped release static archives under release/ascon/<config>/<arch>/libverum.a.
Prints the SHA-256 of each library tested and outputs complete performance metrics.
"""

import os
import sys
import re
import glob
import argparse
import subprocess

# Add scripts directory to path to import _common
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from _common import (
    REPO_ROOT, RELEASE_DIR, BENCH_SOURCES, BENCH_INCLUDES, ALL_HEADERS,
    CONFIGS, ARCH_SPECS, compute_sha256, needs_rebuild, get_release_lib
)

from release.run_release import build_single_config

FN_SYMBOL_MAP = {
    "p12": "run_p12",
    "p8": "run_p8",
    "aead_enc": "VERUM_ASCON_AEAD128_encrypt",
    "aead_dec": "VERUM_ASCON_AEAD128_decrypt",
    "hash256": "VERUM_ASCON_HASH256_digest",
    "xof128": "VERUM_ASCON_XOF128_digest",
    "cxof128": "VERUM_ASCON_CXOF128_digest"
}

def get_text_size(elf_path):
    try:
        res = subprocess.check_output(["llvm-size", elf_path], text=True)
        lines = res.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            return int(parts[0])
    except Exception:
        pass
    return 0

def get_function_sizes(elf_path):
    try:
        out = subprocess.check_output(["llvm-nm", "--print-size", "-C", elf_path], text=True)
        sizes = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2].upper() in ("T", "W"):
                try:
                    sizes[parts[3]] = int(parts[1], 16)
                except ValueError:
                    pass
        return sizes
    except Exception:
        return {}

def get_release_static_stack(arch, cfg_name):
    su_dir = os.path.join(RELEASE_DIR, "verum", cfg_name, "stack_usage", arch)
    stacks = {}
    if not os.path.isdir(su_dir):
        return stacks
    for su_file in glob.glob(os.path.join(su_dir, "*.su")):
        try:
            with open(su_file, "r") as f:
                for line in f:
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        fn = parts[0].split(":")[-1]
                        try:
                            stacks[fn] = int(parts[1])
                        except ValueError:
                            pass
        except Exception:
            pass
    return stacks

def analyze_insn_mix(elf_path, arch):
    try:
        out = subprocess.check_output(["llvm-objdump", "-d", "--no-show-raw-insn", elf_path], text=True)
    except Exception:
        return {"ALU": 0.0, "Shift/Rotate": 0.0, "Load/Store": 0.0, "Branch": 0.0, "Other": 0.0}

    in_target = False
    counts = {"ALU": 0, "Shift/Rotate": 0, "Load/Store": 0, "Branch": 0, "Other": 0}
    
    for line in out.splitlines():
        if "<VERUM_ASCON_" in line:
            in_target = True
            continue
        elif line.endswith(">:") and "<" in line:
            in_target = False
            continue
        if not in_target:
            continue
        m = re.match(r"^\s*[0-9a-f]+:\s+([a-z0-9_.]+)(.*)", line)
        if not m:
            continue
        op = m.group(1).split(".")[0]
        args = m.group(2)
        
        if arch == "arm":
            if any(x in args for x in ["ror", "lsl", "lsr", "asr"]) or op in ["ror", "lsl", "lsr", "asr", "rrx"]:
                counts["Shift/Rotate"] += 1
            elif any(op.startswith(x) for x in ["ldr", "str", "ldm", "stm", "push", "pop"]):
                counts["Load/Store"] += 1
            elif op.startswith("b") or op in ["cbz", "cbnz", "it"]:
                counts["Branch"] += 1
            elif any(op.startswith(x) for x in ["add", "sub", "and", "orr", "eor", "bic", "orn", "mvn", "mov", "cmp", "cmn", "tst", "teq", "rsb", "adc", "sbc"]):
                counts["ALU"] += 1
            else:
                counts["Other"] += 1
        else: # riscv
            if any(op.startswith(x) for x in ["sll", "srl", "sra", "ror", "rol"]):
                counts["Shift/Rotate"] += 1
            elif any(op.startswith(x) for x in ["lw", "sw", "lb", "sb", "lh", "sh"]):
                counts["Load/Store"] += 1
            elif any(op.startswith(x) for x in ["beq", "bne", "blt", "bge", "jal", "j"]):
                counts["Branch"] += 1
            elif any(op.startswith(x) for x in ["add", "sub", "and", "or", "xor", "not", "neg", "mv", "li", "lui", "auipc", "slt"]):
                counts["ALU"] += 1
            else:
                counts["Other"] += 1
                
    total = sum(counts.values())
    return {k: round(v * 100.0 / total, 1) if total else 0.0 for k, v in counts.items()}

def parse_benchmark_output(output):
    matches = re.findall(r"BENCH:op=(\w+),bytes=(\d+),cycles=(\d+),insns=(\d+),peak_stack=(\d+),status=(\w+)", output)
    ops = {}
    for op_name, b_str, c_str, i_str, stk_str, stat_str in matches:
        b = int(b_str)
        c = int(c_str)
        i = int(i_str)
        stk = int(stk_str)
        ops[op_name] = {
            "bytes": b,
            "cycles": c,
            "insns": i,
            "peak_stack": stk,
            "status": stat_str,
            "cyc_byte": round(c / b, 1) if b else c,
            "insn_byte": round(i / b, 1) if b else i
        }
    return ops

def run_bench_arm(build_dir, cfg_filter=None, force=False, opt_flag=None):
    os.makedirs(build_dir, exist_ok=True)
    link_ld = os.path.join(REPO_ROOT, "benchmark", "arch", "arm", "link.ld")
    startup_c = os.path.join(REPO_ROOT, "benchmark", "arch", "arm", "startup.c")
    results = []
    insn_mixes = []
    shas = {}

    selected_configs = [c for c in CONFIGS if (cfg_filter is None or cfg_filter == "all" or c[0] == cfg_filter)]

    print(f"[*] Benchmarking ARM Cortex-M4 across {len(selected_configs)} configurations...")
    for name, defs in selected_configs:
        cfg_dir = os.path.join(build_dir, name)
        os.makedirs(cfg_dir, exist_ok=True)
        lib_path = get_release_lib(name, "arm")

        if not os.path.exists(lib_path) or opt_flag:
            build_single_config("arm", name, defs, RELEASE_DIR, force=(force or bool(opt_flag)), opt_flag=opt_flag)

        lib_sha = compute_sha256(lib_path)
        shas[name] = lib_sha

        elf = os.path.join(cfg_dir, f"bench_arm_{name}.elf")
        bench_deps = BENCH_SOURCES + [startup_c, link_ld, lib_path]

        if force or opt_flag or needs_rebuild(elf, bench_deps):
            compile_cmd = [
                "clang",
                "--target=armv7em-none-eabi",
                "-mcpu=cortex-m4",
                "-mthumb",
                "-mfloat-abi=soft",
                "-ffreestanding",
                "-nostdlib",
                "-O2",
                "-ffunction-sections",
            ] + defs + BENCH_INCLUDES + ["-c"] + BENCH_SOURCES + [startup_c]
            subprocess.check_call(compile_cmd, cwd=cfg_dir)

            bench_objs = [os.path.join(cfg_dir, os.path.splitext(os.path.basename(s))[0] + ".o") for s in BENCH_SOURCES + [startup_c]]
            link_cmd = [
                "clang",
                "--target=armv7em-none-eabi",
                "-mcpu=cortex-m4",
                "-mthumb",
                "-mfloat-abi=soft",
                "-ffreestanding",
                "-nostdlib",
                "-O2",
                "-fuse-ld=lld",
                f"-Wl,-T,{link_ld}",
                "-o", elf
            ] + bench_objs + [lib_path]
            subprocess.check_call(link_cmd)

        qemu_cmd = [
            "qemu-system-arm",
            "-machine", "mps2-an386",
            "-cpu", "cortex-m4",
            "-nographic",
            "-semihosting-config", "enable=on,target=native",
            "-icount", "shift=0",
            "-kernel", elf
        ]
        proc = subprocess.run(qemu_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        output = proc.stdout + proc.stderr
        ops = parse_benchmark_output(output)

        fn_sizes = get_function_sizes(elf)
        fn_stacks = get_release_static_stack("arm", name)
        text_size = get_text_size(elf)
        mix = analyze_insn_mix(elf, "arm")

        results.append((name, ops, fn_sizes, fn_stacks, text_size))
        insn_mixes.append((name, mix))

    return results, insn_mixes, shas

def run_bench_riscv(build_dir, cfg_filter=None, force=False, opt_flag=None):
    os.makedirs(build_dir, exist_ok=True)
    link_ld = os.path.join(REPO_ROOT, "benchmark", "arch", "riscv", "link.ld")
    startup_c = os.path.join(REPO_ROOT, "benchmark", "arch", "riscv", "startup.c")
    results = []
    insn_mixes = []
    shas = {}

    selected_configs = [c for c in CONFIGS if (cfg_filter is None or cfg_filter == "all" or c[0] == cfg_filter)]

    print(f"[*] Benchmarking RISC-V 32 RV32IMAC across {len(selected_configs)} configurations...")
    for name, defs in selected_configs:
        cfg_dir = os.path.join(build_dir, name)
        os.makedirs(cfg_dir, exist_ok=True)
        lib_path = get_release_lib(name, "riscv")

        if not os.path.exists(lib_path) or opt_flag:
            build_single_config("riscv", name, defs, RELEASE_DIR, force=(force or bool(opt_flag)), opt_flag=opt_flag)

        lib_sha = compute_sha256(lib_path)
        shas[name] = lib_sha

        elf = os.path.join(cfg_dir, f"bench_riscv_{name}.elf")
        bench_deps = BENCH_SOURCES + [startup_c, link_ld, lib_path]

        if force or opt_flag or needs_rebuild(elf, bench_deps):
            compile_cmd = [
                "clang",
                "--target=riscv32-unknown-elf",
                "-march=rv32imac_zicsr",
                "-mabi=ilp32",
                "-mcmodel=medany",
                "-ffreestanding",
                "-nostdlib",
                "-O2",
                "-ffunction-sections",
            ] + defs + BENCH_INCLUDES + ["-c"] + BENCH_SOURCES + [startup_c]
            subprocess.check_call(compile_cmd, cwd=cfg_dir)

            bench_objs = [os.path.join(cfg_dir, os.path.splitext(os.path.basename(s))[0] + ".o") for s in BENCH_SOURCES + [startup_c]]
            link_cmd = [
                "clang",
                "--target=riscv32-unknown-elf",
                "-march=rv32imac_zicsr",
                "-mabi=ilp32",
                "-mcmodel=medany",
                "-ffreestanding",
                "-nostdlib",
                "-O2",
                "-fuse-ld=lld",
                f"-Wl,-T,{link_ld}",
                "-o", elf
            ] + bench_objs + [lib_path]
            subprocess.check_call(link_cmd)

        qemu_cmd = [
            "qemu-system-riscv32",
            "-machine", "virt",
            "-cpu", "sifive-e31",
            "-bios", "none",
            "-m", "8M",
            "-nographic",
            "-semihosting-config", "enable=on,target=native",
            "-icount", "shift=0",
            "-kernel", elf
        ]
        proc = subprocess.run(qemu_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        output = proc.stdout + proc.stderr
        ops = parse_benchmark_output(output)

        fn_sizes = get_function_sizes(elf)
        fn_stacks = get_release_static_stack("riscv", name)
        text_size = get_text_size(elf)
        mix = analyze_insn_mix(elf, "riscv")

        results.append((name, ops, fn_sizes, fn_stacks, text_size))
        insn_mixes.append((name, mix))

    return results, insn_mixes, shas

OPERATIONS = [
    {
        "id": "p12",
        "title": "Ascon-p[12] Permutation (12 rounds)",
        "fn": "run_p12",
        "unit": "call"
    },
    {
        "id": "p8",
        "title": "Ascon-p[8] Permutation (8 rounds)",
        "fn": "run_p8",
        "unit": "call"
    },
    {
        "id": "aead_enc",
        "title": "VERUM_ASCON_AEAD128_encrypt (32B Message Payload)",
        "fn": "VERUM_ASCON_AEAD128_encrypt",
        "unit": "byte"
    },
    {
        "id": "aead_dec",
        "title": "VERUM_ASCON_AEAD128_decrypt (32B Ciphertext Payload)",
        "fn": "VERUM_ASCON_AEAD128_decrypt",
        "unit": "byte"
    },
    {
        "id": "hash256",
        "title": "VERUM_ASCON_HASH256_digest (32B Message -> 32B Digest)",
        "fn": "VERUM_ASCON_HASH256_digest",
        "unit": "byte"
    },
    {
        "id": "xof128",
        "title": "VERUM_ASCON_XOF128_digest (32B Message -> 32B Digest)",
        "fn": "VERUM_ASCON_XOF128_digest",
        "unit": "byte"
    },
    {
        "id": "cxof128",
        "title": "VERUM_ASCON_CXOF128_digest (32B Message, 2B Customization -> 32B Digest)",
        "fn": "VERUM_ASCON_CXOF128_digest",
        "unit": "byte"
    },
]

def get_op_footprint(op_id, fn_sizes, fn_stacks):
    if op_id in ("p12", "p8"):
        if "VERUM_ASCON_permute" in fn_sizes:
            code_sz = fn_sizes.get("VERUM_ASCON_permute", 0)
            stk_sz = fn_stacks.get("VERUM_ASCON_permute", 0)
        else:
            code_sz = (fn_sizes.get("VERUM_ASCON_permute_substitution_layer", 0) +
                       fn_sizes.get("VERUM_ASCON_permute_merged", 0) +
                       fn_sizes.get("VERUM_ASCON_permute_linear_diffusion_layer", 0))
            stk_sz = max(fn_stacks.get("VERUM_ASCON_permute_substitution_layer", 0),
                         fn_stacks.get("VERUM_ASCON_permute_merged", 0),
                         fn_stacks.get("VERUM_ASCON_permute_linear_diffusion_layer", 0))
        return code_sz, stk_sz
    elif op_id == "aead_enc":
        return fn_sizes.get("VERUM_ASCON_AEAD128_encrypt", 0), fn_stacks.get("VERUM_ASCON_AEAD128_encrypt", 0)
    elif op_id == "aead_dec":
        return fn_sizes.get("VERUM_ASCON_AEAD128_decrypt", 0), fn_stacks.get("VERUM_ASCON_AEAD128_decrypt", 0)
    elif op_id == "hash256":
        return fn_sizes.get("VERUM_ASCON_HASH256_digest", 0), fn_stacks.get("VERUM_ASCON_HASH256_digest", 0)
    elif op_id == "xof128":
        return fn_sizes.get("VERUM_ASCON_XOF128_digest", 0), fn_stacks.get("VERUM_ASCON_XOF128_digest", 0)
    elif op_id == "cxof128":
        return fn_sizes.get("VERUM_ASCON_CXOF128_digest", 0), fn_stacks.get("VERUM_ASCON_CXOF128_digest", 0)
    return 0, 0

def print_tables(title, results, insn_mixes, shas, fn_filter="all"):
    print("=" * 135)
    print(f"Target: {title}")
    print("=" * 135)

    print("\nCryptographic SHA-256 of Libraries Under Test:")
    for name, sha in shas.items():
        print(f"  {name:<30} : {sha}")
    print("-" * 135)

    # 1. High-Level Configuration Matrix Summary
    print(f"\n[1] Overall Performance Matrix Summary:")
    print(f"{'Configuration':<30} {'p[12](cyc)':>11} {'p[8](cyc)':>10} {'AEAD-E(c/B)':>12} {'AEAD-D(c/B)':>12} {'Hash(c/B)':>10} {'XOF(c/B)':>9} {'CXOF(c/B)':>10} {'Peak Stk':>9} {'.text (B)':>10} {'Status':>8}")
    print("-" * 135)
    for name, ops, fn_sizes, fn_stacks, txt in results:
        p12_cyc = ops.get("p12", {}).get("cycles", 0)
        p8_cyc = ops.get("p8", {}).get("cycles", 0)
        enc_cb = ops.get("aead_enc", {}).get("cyc_byte", 0.0)
        dec_cb = ops.get("aead_dec", {}).get("cyc_byte", 0.0)
        hash_cb = ops.get("hash256", {}).get("cyc_byte", 0.0)
        xof_cb = ops.get("xof128", {}).get("cyc_byte", 0.0)
        cxof_cb = ops.get("cxof128", {}).get("cyc_byte", 0.0)
        
        peak_stk = max((v["peak_stack"] for v in ops.values()), default=0)
        all_passed = all(v.get("status") == "PASSED" for v in ops.values()) and len(ops) >= 7
        status_str = "PASSED" if all_passed else "FAILED"

        print(f"{name:<30} {p12_cyc:>11} {p8_cyc:>10} {enc_cb:>12.1f} {dec_cb:>12.1f} {hash_cb:>10.1f} {xof_cb:>9.1f} {cxof_cb:>10.1f} {peak_stk:>9} {txt:>10} {status_str:>8}")
    print("=" * 135)

    # 2. Individual Per-Function / Per-Operation Footprint & Cost Breakdown
    selected_ops = [op for op in OPERATIONS if (fn_filter == "all" or fn_filter == op["id"] or fn_filter == op["fn"])]
    if selected_ops and fn_filter != "summary":
        print(f"\n[2] Detailed Per-Function Footprint (Code Size & Static/Peak Stack) & Cost (Cycles & Insns):")
        for op in selected_ops:
            op_id = op["id"]
            cost_col = "Cyc/Byte" if op["unit"] == "byte" else "Cyc/Call"
            insn_col = "Insn/Byte" if op["unit"] == "byte" else "Insn/Call"

            print(f"\n>>> Function / Operation: {op['title']}")
            print(f"{'Configuration':<30} {'Code (B)':>10} {'Static Stk (B)':>15} {'Peak Stk (B)':>13} {'Cycles':>12} {'Insns':>12} {cost_col:>11} {insn_col:>11} {'Status':>10}")
            print("-" * 135)
            for name, ops, fn_sizes, fn_stacks, txt in results:
                op_data = ops.get(op_id, {})
                cyc = op_data.get("cycles", 0)
                insn = op_data.get("insns", 0)
                peak_stk = op_data.get("peak_stack", 0)
                stat = op_data.get("status", "N/A")
                cyc_rate = op_data.get("cyc_byte", 0.0)
                insn_rate = op_data.get("insn_byte", 0.0)

                code_sz, stk_sz = get_op_footprint(op_id, fn_sizes, fn_stacks)

                if op["unit"] == "byte":
                    cyc_rate_str = f"{cyc_rate:.1f}"
                    insn_rate_str = f"{insn_rate:.1f}"
                else:
                    cyc_rate_str = f"{cyc}"
                    insn_rate_str = f"{insn}"

                print(f"{name:<30} {code_sz:>10} {stk_sz:>15} {peak_stk:>13} {cyc:>12} {insn:>12} {cyc_rate_str:>11} {insn_rate_str:>11} {stat:>10}")
            print("-" * 135)
        print("=" * 135)

    # 3. Instruction Mix Distribution Table
    print("\n[3] Instruction Mix Distribution (Ascon Core):")
    print(f"{'Configuration':<30} {'ALU (%)':>10} {'Shift/Rotate (%)':>18} {'Load/Store (%)':>16} {'Branch (%)':>12} {'Other (%)':>11}")
    print("-" * 135)
    for name, mix in insn_mixes:
        print(f"{name:<30} {mix['ALU']:>10.1f} {mix['Shift/Rotate']:>18.1f} {mix['Load/Store']:>16.1f} {mix['Branch']:>12.1f} {mix['Other']:>11.1f}")
    print("=" * 135)
    print()

def main():
    parser = argparse.ArgumentParser(description="Run QEMU benchmarks against release static archives.")
    parser.add_argument("--arch", choices=["arm", "riscv", "all"], default="all",
                        help="Target architecture (default: all)")
    parser.add_argument("--config", default="all",
                        help="Configuration name to benchmark (default: all)")
    parser.add_argument("--function", "--fn", default="all",
                        help="Specific function/operation to report ('all', 'summary', 'p12', 'p8', 'aead_enc', 'aead_dec', 'hash256', 'xof128', 'cxof128')")
    parser.add_argument("--opt", default=None,
                        help="Optional optimization flag override for libverum (default: None, uses -O0 from CMakeLists.txt)")
    parser.add_argument("--build-dir", default=os.path.join(REPO_ROOT, "build", "benchmark"),
                        help="Benchmark output build directory")
    parser.add_argument("--force", action="store_true",
                        help="Force rebuild of harness and binaries")
    args = parser.parse_args()

    build_base = os.path.abspath(args.build_dir)
    os.makedirs(build_base, exist_ok=True)

    if args.arch in ("arm", "all"):
        arm_dir = os.path.join(build_base, "arm")
        arm_res, arm_mix, arm_shas = run_bench_arm(arm_dir, cfg_filter=args.config, force=args.force, opt_flag=args.opt)
        print_tables("ARM Cortex-M4 (ARMv7E-M, QEMU mps2-an386)", arm_res, arm_mix, arm_shas, fn_filter=args.function)

    if args.arch in ("riscv", "all"):
        riscv_dir = os.path.join(build_base, "riscv")
        rv_res, rv_mix, rv_shas = run_bench_riscv(riscv_dir, cfg_filter=args.config, force=args.force, opt_flag=args.opt)
        print_tables("RISC-V 32 RV32IMAC (QEMU virt sifive-e31)", rv_res, rv_mix, rv_shas, fn_filter=args.function)

if __name__ == "__main__":
    main()
