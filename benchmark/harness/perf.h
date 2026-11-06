/**
 * @file      perf.h
 * @brief     Hardware performance counter and stack watermark abstraction.
 * @details   Supports ARM Cortex-M SysTick and RISC-V 32 CSR minstret/mcycle.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_BENCH_PERF_H_
#define VERUM_BENCH_PERF_H_

#include "standard/types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern uint32_t __stack_top;
extern uint32_t __stack_bottom;

#if defined(__arm__) || defined(__thumb__)

#define VERUM_BENCH_SYST_CSR (*(volatile uint32_t *) 0xE000E010U)
#define VERUM_BENCH_SYST_RVR (*(volatile uint32_t *) 0xE000E014U)
#define VERUM_BENCH_SYST_CVR (*(volatile uint32_t *) 0xE000E018U)

/**
 * @details Under QEMU mps2-an386 with -icount shift=0 (1 GHz virtual CPU clock),
 *          the Cortex-M SysTick timer is clocked by the board 25 MHz reference clock.
 *          Therefore, 1 SysTick tick = exactly 40 CPU instructions / clock cycles.
 */
#define VERUM_BENCH_SYSTICK_TO_CPU_CYCLES 40U

static inline void perf_init(void)
{
    VERUM_BENCH_SYST_RVR = 0x00FFFFFFU;
    VERUM_BENCH_SYST_CVR = 0x00000000U;
    VERUM_BENCH_SYST_CSR = 0x00000005U; /* CPU clock, enabled */
}

static inline uint32_t perf_cycles_read(void)
{
    return VERUM_BENCH_SYST_CVR;
}

static inline uint32_t perf_cycles_diff(uint32_t start,
                                        uint32_t stop)
{
    uint32_t ticks = (start - stop) & 0x00FFFFFFU;
    return ticks * VERUM_BENCH_SYSTICK_TO_CPU_CYCLES;
}

static inline uint32_t perf_insn_read(void)
{
    return VERUM_BENCH_SYST_CVR;
}

static inline uint32_t perf_insn_diff(uint32_t start,
                                      uint32_t stop)
{
    uint32_t ticks = (start - stop) & 0x00FFFFFFU;
    return ticks * VERUM_BENCH_SYSTICK_TO_CPU_CYCLES;
}

static inline uint32_t perf_get_sp(void)
{
    uint32_t sp_val;
    __asm__ volatile ("mov %0, sp" : "=r" (sp_val));
    return sp_val;
}

#elif defined(__riscv)

static inline void perf_init(void)
{
    /* CSR counters are always active in M-mode */
}

static inline uint32_t perf_cycles_read(void)
{
    uint32_t val;
    __asm__ volatile ("csrr %0, mcycle" : "=r" (val));
    return val;
}

static inline uint32_t perf_cycles_diff(uint32_t start,
                                        uint32_t stop)
{
    return stop - start;
}

static inline uint32_t perf_insn_read(void)
{
    uint32_t val;
    __asm__ volatile ("csrr %0, minstret" : "=r" (val));
    return val;
}

static inline uint32_t perf_insn_diff(uint32_t start,
                                      uint32_t stop)
{
    return stop - start;
}

static inline uint32_t perf_get_sp(void)
{
    uint32_t sp_val;
    __asm__ volatile ("mv %0, sp" : "=r" (sp_val));
    return sp_val;
}

#endif

#define VERUM_BENCH_STACK_CANARY 0xA5U

static inline void perf_stack_paint(void)
{
    uint8_t *bottom = (uint8_t *) &__stack_bottom;
    const uint8_t *top = (const uint8_t *) (perf_get_sp() - 32U);
    while (bottom < top)
    {
        *bottom = VERUM_BENCH_STACK_CANARY;
        bottom++;
    }
}

static inline uint32_t perf_stack_peak(uint32_t caller_sp)
{
    const uint8_t *bottom = (const uint8_t *) &__stack_bottom;
    const uint8_t *top = (const uint8_t *) caller_sp;
    while ((bottom < top) && (*bottom == VERUM_BENCH_STACK_CANARY))
    {
        bottom++;
    }
    return (uint32_t) (top - bottom);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* VERUM_BENCH_PERF_H_ */
