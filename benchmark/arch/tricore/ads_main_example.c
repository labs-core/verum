/**
 * @file      ads_main_example.c
 * @brief     Example Core0 entry for running the Verum benchmark inside AURIX Development Studio.
 * @details   NOT compiled by the QEMU builder. Copy into an ADS project (replace Cpu0_Main.c body),
 *            together with the sources listed in README.md.
 *
 *            Results: after bench_ascon_run() returns, read the symbol verum_bench_log in the
 *            debugger (NUL-terminated "BENCH:op=...,cycles=..." lines), or override
 *            verum_bench_putc() to send characters to an ASCLIN UART.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */

#include "harness/perf.h"
#include "harness/semihost.h"
#include "suite/ascon/bench_ascon.h"

/* Stack watermark: build with -DVERUM_BENCH_STACK_BOTTOM_DEF='((uint32_t) &<lowest-stack-symbol-of-your-.ld>)'
 * (default is __stack_bottom from the TriCore QEMU linker script). */

void core0_main(void)
{
    perf_init(); /* enables CCNT / ICNT */
    int rc = bench_ascon_run();
    semihost_exit((uint32_t) rc); /* breakpoint here; results are in verum_bench_log */
}
