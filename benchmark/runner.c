/**
 * @file      runner.c
 * @brief     Bare-metal benchmark runner main entry point.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */

#include "define.h"
#include "harness/perf.h"
#include "harness/semihost.h"
#include "macro.h"

#include "suite/ascon/bench_ascon.h"

VERUM_ATTR_NORETURN void VERUM_FAULT_HANDLER(void);
VERUM_ATTR_NORETURN void VERUM_FAULT_HANDLER(void)
{
    semihost_puts("FATAL: VERUM_FAULT_HANDLER called\n");
    semihost_exit(1);
    while (1)
    {
    }
}
int main(void)
{
    perf_init();
    int rc = bench_ascon_run();
    return rc;
}
