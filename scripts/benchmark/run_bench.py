#!/usr/bin/env python3
"""
Bare-metal QEMU benchmark & evaluation driver for ARM Cortex-M4 and RISC-V 32 RV32IMAC.
Measures transitive code size, static and dynamic stack footprint, cycle/instruction scaling
across 32B, 512B, and 1024B, asymptotic rates, overhead, and instruction mix.
Outputs clean diffable logs compatible with reference ascon-c evaluation.
"""

import os
import sys
import re
import glob
import argparse
import subprocess
import shutil

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from _common import (
    REPO_ROOT, RELEASE_DIR, BENCH_SOURCES, BENCH_INCLUDES, ALL_HEADERS,
    CONFIGS, ARCH_SPECS, compute_sha256, needs_rebuild, get_release_lib
)

from release.run_release import build_single_config

ARCH_INFO = {
    "arm": {
        "title": "ARM Cortex-M4 (ARMv7E-M, QEMU mps2-an386)",
        "target": "armv7em-none-eabi",
        "mcpu": "-mcpu=cortex-m4",
        "mthumb": "-mthumb",
        "abi": "-mfloat-abi=soft",
        "startup": os.path.join(REPO_ROOT, "benchmark", "arch", "arm", "startup.c"),
        "link_ld": os.path.join(REPO_ROOT, "benchmark", "arch", "arm", "link.ld"),
        "qemu_cmd": [
            "qemu-system-arm",
            "-machine", "mps2-an386",
            "-cpu", "cortex-m4",
            "-nographic",
            "-semihosting-config", "enable=on,target=native",
            "-icount", "shift=0"
        ]
    },
    "riscv": {
        "title": "RISC-V 32 (RV32IMAC, QEMU virt sifive-e31)",
        "target": "riscv32-unknown-elf",
        "march": "-march=rv32imac_zicsr",
        "mabi": "-mabi=ilp32",
        "mcmodel": "-mcmodel=medany",
        "startup": os.path.join(REPO_ROOT, "benchmark", "arch", "riscv", "startup.c"),
        "link_ld": os.path.join(REPO_ROOT, "benchmark", "arch", "riscv", "link.ld"),
        "qemu_cmd": [
            "qemu-system-riscv32",
            "-machine", "virt",
            "-cpu", "sifive-e31",
            "-bios", "none",
            "-m", "8M",
            "-nographic",
            "-semihosting-config", "enable=on,target=native",
            "-icount", "shift=0"
        ]
    }
}

OPERATIONS = [
    {
        "id": "aead_enc",
        "title": "VERUM_ASCON_AEAD128_encrypt",
        "root_fn": "VERUM_ASCON_AEAD128_encrypt"
    },
    {
        "id": "aead_dec",
        "title": "VERUM_ASCON_AEAD128_decrypt",
        "root_fn": "VERUM_ASCON_AEAD128_decrypt"
    },
    {
        "id": "hash256",
        "title": "VERUM_ASCON_HASH256_digest",
        "root_fn": "VERUM_ASCON_HASH256_digest"
    },
    {
        "id": "xof128",
        "title": "VERUM_ASCON_XOF128_digest",
        "root_fn": "VERUM_ASCON_XOF128_digest"
    },
    {
        "id": "cxof128",
        "title": "VERUM_ASCON_CXOF128_digest",
        "root_fn": "VERUM_ASCON_CXOF128_digest"
    }
]

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
        out = subprocess.check_output(["llvm-nm", "--print-size", "--numeric-sort", elf_path], text=True)
    except Exception:
        return {}
    sizes = {}
    symbols_in_order = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[1].upper() in ("T", "R", "D", "W") or (len(parts) >= 4 and parts[2].upper() in ("T", "R", "D", "W")):
            if len(parts) == 3:
                addr = int(parts[0], 16)
                name = parts[2]
                size = 0
            else:
                addr = int(parts[0], 16)
                size = int(parts[1], 16)
                name = parts[3]
            sizes[name] = size
            symbols_in_order.append((addr, name, size))

    for idx in range(len(symbols_in_order)):
        addr, name, sz = symbols_in_order[idx]
        if sz == 0:
            if idx + 1 < len(symbols_in_order):
                next_addr = symbols_in_order[idx + 1][0]
                diff = next_addr - addr
                if 0 < diff < 65536:
                    sizes[name] = diff
    return sizes

def get_transitive_call_graph(elf_path, root_fn):
    try:
        out = subprocess.check_output(["llvm-objdump", "-d", elf_path], text=True)
    except Exception:
        return {root_fn}, {root_fn: set()}

    call_graph = {}
    current_fn = None
    for line in out.splitlines():
        m_fn = re.match(r"^[0-9a-f]+\s+<([A-Za-z0-9_]+)>:", line)
        if m_fn:
            current_fn = m_fn.group(1)
            call_graph[current_fn] = set()
            continue
        if current_fn:
            m_call = re.search(r"\b(?:bl|jal|call[q]?|b\.w|b|j|tail)\s+.*<([A-Za-z0-9_]+)>", line)
            if m_call:
                callee = m_call.group(1)
                if callee != current_fn and not callee.startswith("semihost_") and not callee.startswith("perf_"):
                    call_graph[current_fn].add(callee)

    visited = set()
    queue = [root_fn]
    while queue:
        curr = queue.pop(0)
        if curr in visited:
            continue
        visited.add(curr)
        for callee in call_graph.get(curr, []):
            if callee not in visited:
                queue.append(callee)

    return visited, call_graph

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

def get_call_graph_stack(root_fn, call_graph, fn_stacks, memo=None, visiting=None):
    if memo is None:
        memo = {}
    if visiting is None:
        visiting = set()
    if root_fn in memo:
        return memo[root_fn]
    if root_fn in visiting:
        return 0
    visiting.add(root_fn)
    callee_max = 0
    for callee in call_graph.get(root_fn, []):
        callee_max = max(callee_max, get_call_graph_stack(callee, call_graph, fn_stacks, memo, visiting))
    visiting.remove(root_fn)
    res = fn_stacks.get(root_fn, 0) + callee_max
    memo[root_fn] = res
    return res

def analyze_insn_mix(elf_path, arch):
    try:
        out = subprocess.check_output(["llvm-objdump", "-d", "--no-show-raw-insn", elf_path], text=True)
    except Exception:
        return {"ALU": 0.0, "Shift/Rotate": 0.0, "Load/Store": 0.0, "Branch": 0.0, "Other": 0.0}

    in_target = False
    counts = {"ALU": 0, "Shift/Rotate": 0, "Load/Store": 0, "Branch": 0, "Other": 0}

    for line in out.splitlines():
        m_fn = re.match(r"^[0-9a-f]+\s+<([A-Za-z0-9_]+)>:", line)
        if m_fn:
            fn = m_fn.group(1)
            in_target = fn.startswith("VERUM_ASCON_")
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
    metrics = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("BENCH:"):
            parts = line[6:].split(",")
            d = {}
            for p in parts:
                if "=" in p:
                    k, v = p.split("=", 1)
                    d[k] = v
            op = d.get("op")
            if op:
                if op not in metrics:
                    metrics[op] = []
                metrics[op].append({
                    "bytes": int(d.get("bytes", 0)),
                    "cycles": int(d.get("cycles", 0)),
                    "insns": int(d.get("insns", 0)),
                    "peak_stack": int(d.get("peak_stack", 0)),
                    "status": d.get("status", "UNKNOWN")
                })
    return metrics

def run_bench_arch(arch, build_dir, cfg_filter=None, fips_mode=None, force=False, opt_flag=None):
    os.makedirs(build_dir, exist_ok=True)
    ainfo = ARCH_INFO[arch]
    startup_c = ainfo["startup"]
    link_ld = ainfo["link_ld"]

    results = []
    insn_mixes = []
    shas = {}

    selected_configs = []
    for c in CONFIGS:
        if cfg_filter and cfg_filter != "all" and c[0] != cfg_filter:
            continue
        # Preinterleave and associated data only affect AEAD; do not compile preinterleaved configs in benchmark matrix
        if cfg_filter == "all" and "preinterleaved" in c[0]:
            continue
        is_fips = c[0].startswith("fips_")
        if fips_mode is True and not is_fips:
            continue
        if fips_mode is False and is_fips:
            continue
        selected_configs.append(c)

    print(f"[*] Benchmarking {ainfo['title']} across {len(selected_configs)} configurations...")
    for name, defs in selected_configs:
        cfg_dir = os.path.join(build_dir, name)
        os.makedirs(cfg_dir, exist_ok=True)
        lib_path = get_release_lib(name, arch)

        if not os.path.exists(lib_path) or force or opt_flag:
            build_single_config(arch, name, defs, RELEASE_DIR, force=(force or bool(opt_flag)), opt_flag=opt_flag)

        lib_sha = compute_sha256(lib_path)
        shas[name] = lib_sha

        elf = os.path.join(cfg_dir, f"bench_{arch}_{name}.elf")
        bench_deps = BENCH_SOURCES + [startup_c, link_ld, lib_path]

        if force or opt_flag or needs_rebuild(elf, bench_deps):
            if arch == "arm":
                compile_cmd = [
                    "clang",
                    f"--target={ainfo['target']}",
                    ainfo["mcpu"],
                    ainfo["mthumb"],
                    ainfo["abi"],
                    "-ffreestanding",
                    "-nostdlib",
                    "-O2",
                    "-ffunction-sections",
                ] + defs + BENCH_INCLUDES + ["-c"] + BENCH_SOURCES + [startup_c]
            else:
                compile_cmd = [
                    "clang",
                    f"--target={ainfo['target']}",
                    ainfo["march"],
                    ainfo["mabi"],
                    ainfo["mcmodel"],
                    "-ffreestanding",
                    "-nostdlib",
                    "-O2",
                    "-ffunction-sections",
                ] + defs + BENCH_INCLUDES + ["-c"] + BENCH_SOURCES + [startup_c]

            subprocess.check_call(compile_cmd, cwd=cfg_dir)

            bench_objs = [os.path.join(cfg_dir, os.path.splitext(os.path.basename(s))[0] + ".o") for s in BENCH_SOURCES + [startup_c]]
            
            if arch == "arm":
                link_cmd = [
                    "clang",
                    f"--target={ainfo['target']}",
                    ainfo["mcpu"],
                    ainfo["mthumb"],
                    ainfo["abi"],
                    "-ffreestanding",
                    "-nostdlib",
                    "-O2",
                    "-fuse-ld=lld",
                    f"-Wl,-T,{link_ld}",
                    "-Wl,--gc-sections",
                    "-o", elf
                ] + bench_objs + [lib_path]
            else:
                link_cmd = [
                    "clang",
                    f"--target={ainfo['target']}",
                    ainfo["march"],
                    ainfo["mabi"],
                    ainfo["mcmodel"],
                    "-ffreestanding",
                    "-nostdlib",
                    "-O2",
                    "-fuse-ld=lld",
                    f"-Wl,-T,{link_ld}",
                    "-Wl,--gc-sections",
                    "-o", elf
                ] + bench_objs + [lib_path]

            subprocess.check_call(link_cmd)

        qemu_cmd = ainfo["qemu_cmd"] + ["-kernel", elf]
        proc = subprocess.run(qemu_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=40)
        output = proc.stdout + proc.stderr
        metrics = parse_benchmark_output(output)

        fn_sizes = get_function_sizes(elf)
        fn_stacks = get_release_static_stack(arch, name)
        text_size = get_text_size(elf)
        mix = analyze_insn_mix(elf, arch)

        results.append((name, metrics, fn_sizes, fn_stacks, text_size, elf))
        insn_mixes.append((name, mix))

    return results, insn_mixes, shas

def format_verum_tables(arch, results, insn_mixes, shas, fn_filter="all"):
    ainfo = ARCH_INFO[arch]
    title = ainfo["title"]
    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    out("=" * 164)
    out(f"Target: {title}  --  Verum Benchmark Suite")
    out("=" * 164)

    out(f"\n[1] Detailed Per-Function Transitive Footprint & Scaling Breakdown:")

    target_ops = [op for op in OPERATIONS if (fn_filter == "all" or fn_filter == op["id"] or fn_filter == op["root_fn"])]
    
    for op_info in target_ops:
        op_id = op_info["id"]
        root_fn = op_info["root_fn"]
        op_title = op_info["title"]

        has_op = any(op_id in metrics for _, metrics, _, _, _, _ in results)
        if not has_op:
            continue

        out(f"\n>>> Function / Operation: {op_title}")
        out(f"{'Configuration':<33} {'Code (B)':>9} {'Stk(St/Pk)':>11} {'32B cyc':>9} {'32B c/B':>8} {'512B cyc':>11} {'512B c/B':>9} {'1024B cyc':>12} {'1KB c/B':>8} {'Asymp c/B':>10} {'Asymp i/B':>10} {'Overhead (c|i)':>18} {'Status':>8}")
        out("-" * 164)

        for name, metrics, fn_sizes, fn_stacks, text_sz, elf in results:
            # Preinterleave and associated data only affect AEAD; filter out redundant noad rows for non-AEAD ops
            if op_id in ("hash256", "xof128", "cxof128") and "noad" in name:
                continue
            data_list = metrics.get(op_id, [])
            if not data_list:
                continue

            by_bytes = {d["bytes"]: d for d in data_list}
            d32 = by_bytes.get(32, {})
            d512 = by_bytes.get(512, {})
            d1024 = by_bytes.get(1024, {})

            c32 = d32.get("cycles", 0)
            c512 = d512.get("cycles", 0)
            c1024 = d1024.get("cycles", 0)
            i512 = d512.get("insns", 0)
            i1024 = d1024.get("insns", 0)

            c32_rate = c32 / 32.0 if c32 else 0.0
            c512_rate = c512 / 512.0 if c512 else 0.0
            c1024_rate = c1024 / 1024.0 if c1024 else 0.0

            asymp_c_per_b = (c1024 - c512) / 512.0 if (c1024 and c512) else 0.0
            asymp_i_per_b = (i1024 - i512) / 512.0 if (i1024 and i512) else 0.0
            fixed_overhead_c = c1024 - (asymp_c_per_b * 1024.0) if c1024 else 0
            fixed_overhead_i = i1024 - (asymp_i_per_b * 1024.0) if i1024 else 0

            visited, cg = get_transitive_call_graph(elf, root_fn)
            code_size = sum(fn_sizes.get(fn, 0) for fn in visited)
            if any("permute" in f for f in visited):
                code_size += fn_sizes.get("VERUM_ASCON_round_constants", 0)

            static_stack = get_call_graph_stack(root_fn, cg, fn_stacks)
            peak_stack = max(d.get("peak_stack", 0) for d in data_list)

            stk_str = f"{static_stack}/{peak_stack}"
            ovhd_str = f"{int(round(fixed_overhead_c))} | {int(round(fixed_overhead_i))}"
            status = "PASSED" if all(d.get("status") == "PASSED" for d in data_list) else "FAILED"

            out(f"{name:<33} {code_size:>9} {stk_str:>11} {c32:>9} {c32_rate:>8.1f} {c512:>11} {c512_rate:>9.1f} {c1024:>12} {c1024_rate:>8.1f} {asymp_c_per_b:>10.1f} {asymp_i_per_b:>10.1f} {ovhd_str:>18} {status:>8}")

        out("-" * 164)

    # Instruction Mix
    out(f"\n[2] Instruction Mix Distribution (Ascon Core):")
    out(f"{'Configuration':<35} {'ALU (%)':>10} {'Shift/Rotate (%)':>18} {'Load/Store (%)':>16} {'Branch (%)':>12} {'Other (%)':>11}")
    out("-" * 164)
    for name, mix in insn_mixes:
        out(f"{name:<35} {mix['ALU']:>10.1f} {mix['Shift/Rotate']:>18.1f} {mix['Load/Store']:>16.1f} {mix['Branch']:>12.1f} {mix['Other']:>11.1f}")
    out("=" * 164)
    out()

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Run bare-metal QEMU benchmarks against release static archives.")
    parser.add_argument("--arch", choices=["arm", "riscv", "all"], default="all",
                        help="Target architecture (default: all)")
    parser.add_argument("--config", default="all",
                        help="Configuration name to benchmark (default: all)")
    parser.add_argument("--fips", action="store_true", default=False,
                        help="Benchmark only FIPS 140-3 configurations")
    parser.add_argument("--no-fips", action="store_true", default=False,
                        help="Benchmark only non-FIPS configurations")
    parser.add_argument("--function", "--fn", default="all",
                        help="Specific function/operation to report ('all', 'aead_enc', 'aead_dec', 'hash256', 'xof128', 'cxof128')")
    parser.add_argument("--opt", default=None,
                        help="Optional optimization flag override for libverum (default: None, uses -O0 from CMakeLists.txt)")
    parser.add_argument("--build-dir", default=os.path.join(REPO_ROOT, "build", "benchmark"),
                        help="Benchmark output build directory")
    parser.add_argument("--log-file", default=None,
                        help="Log file path to write results (default: build/verum_results_0.log)")
    parser.add_argument("--force", action="store_true",
                        help="Force rebuild of harness and binaries")
    args = parser.parse_args()

    fips_mode = None
    if args.fips and not args.no_fips:
        fips_mode = True
    elif args.no_fips and not args.fips:
        fips_mode = False

    build_base = os.path.abspath(args.build_dir)
    os.makedirs(build_base, exist_ok=True)

    log_path = args.log_file if args.log_file else os.path.join(REPO_ROOT, "build", "verum_results_0.log")
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

    all_logs = []
    archs = ["arm", "riscv"] if args.arch == "all" else [args.arch]

    for arch in archs:
        arch_dir = os.path.join(build_base, arch)
        res, mix, shas = run_bench_arch(arch, arch_dir, cfg_filter=args.config, fips_mode=fips_mode, force=args.force, opt_flag=args.opt)
        log_text = format_verum_tables(arch, res, mix, shas, fn_filter=args.function)
        all_logs.append(log_text)

    full_output = "\n\n".join(all_logs) + "\n"
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(full_output)

    # Also mirror to build/benchmark/verum_results_0.log
    mirror_path = os.path.join(build_base, "verum_results_0.log")
    if os.path.abspath(mirror_path) != os.path.abspath(log_path):
        try:
            with open(mirror_path, "w", encoding="utf-8") as f:
                f.write(full_output)
        except IOError:
            pass

    print(f"[*] Benchmark output successfully written to: {log_path}")

if __name__ == "__main__":
    main()
