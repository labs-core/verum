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

#include "harness/perf.h"
#include "harness/semihost.h"

#include "suite/ascon/bench_ascon.h"
int main(void)
{
    perf_init();
    int rc = bench_ascon_run();
    return rc;
}
