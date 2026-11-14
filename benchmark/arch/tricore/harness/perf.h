/**
 * @file      perf.h
 * @brief     TriCore performance counter and stack watermark abstraction.
 * @details   Replaces benchmark/harness/perf.h for the TriCore GCC build. build.py force-includes
 *            this header (-include) before the shared benchmark sources, so it claims the shared
 *            include guard VERUM_BENCH_PERF_H_ and the Clang harness header is skipped; the shared
 *            Clang harness stays untouched.
 *
 *            Cycles and instructions come from the TC1.6.2 core debug counters:
 *            CCTRL (0xFC00), CCNT (0xFC04, bit 31 = sticky overflow) and ICNT (0xFC08).
 *            These are real on silicon and in the AURIX simulator, but QEMU does not model
 *            them, so QEMU runs report 0 cycles / 0 instructions.
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

#ifndef __tricore__
#error "benchmark/arch/tricore/harness/perf.h requires the TriCore GCC toolchain"
#endif /* __tricore__ */

/** Stack range painted/inspected by the watermark. Override with -D for non-default linker scripts. */
#ifndef VERUM_BENCH_STACK_BOTTOM_DEF
extern uint32_t __stack_bottom;
#define VERUM_BENCH_STACK_BOTTOM_DEF ((uint32_t) &__stack_bottom)
#endif /* VERUM_BENCH_STACK_BOTTOM_DEF */

#define VERUM_BENCH_CCTRL_CE 0x00000002U /* counter enable, normal (non task) mode */
#define VERUM_BENCH_COUNTER_MASK 0x7FFFFFFFU

#ifdef VERUM_TRICORE_QEMU_DEF

/* QEMU: no CCNT/ICNT. Each read stores to a marker address; qemu_trace.py counts the
 * instructions executed between markers from QEMU's execution log (1 instruction = 1 cycle). */
#define VERUM_BENCH_QEMU_MARKER (*(volatile uint32_t *) 0xF2000000U)

static inline void perf_init(void)
{
}

static inline uint32_t perf_cycles_read(void)
{
    VERUM_BENCH_QEMU_MARKER = 0U;
    return 0U;
}

static inline uint32_t perf_insn_read(void)
{
    VERUM_BENCH_QEMU_MARKER = 0U;
    return 0U;
}

#else /* VERUM_TRICORE_QEMU_DEF */

static inline void perf_init(void)
{
    __asm__ volatile ("mtcr 0xFC00, %0\n\tisync" : : "d" (VERUM_BENCH_CCTRL_CE) : "memory");
}

static inline uint32_t perf_cycles_read(void)
{
    uint32_t val;
    __asm__ volatile ("mfcr %0, 0xFC04" : "=d" (val) : : "memory");
    return val;
}

static inline uint32_t perf_insn_read(void)
{
    uint32_t val;
    __asm__ volatile ("mfcr %0, 0xFC08" : "=d" (val) : : "memory");
    return val;
}

#endif /* VERUM_TRICORE_QEMU_DEF */

static inline uint32_t perf_cycles_diff(uint32_t start,
                                        uint32_t stop)
{
    return (stop - start) & VERUM_BENCH_COUNTER_MASK;
}

static inline uint32_t perf_insn_diff(uint32_t start,
                                      uint32_t stop)
{
    return (stop - start) & VERUM_BENCH_COUNTER_MASK;
}

static inline uint32_t perf_get_sp(void)
{
    uint32_t sp_val;
    __asm__ volatile ("mov.d %0, %%a10" : "=d" (sp_val));
    return sp_val;
}

#define VERUM_BENCH_STACK_CANARY 0xA5U

static inline void perf_stack_paint(void)
{
    uint8_t *bottom = (uint8_t *) VERUM_BENCH_STACK_BOTTOM_DEF;
    const uint8_t *top = (const uint8_t *) (perf_get_sp() - 32U);
    while (bottom < top)
    {
        *bottom = VERUM_BENCH_STACK_CANARY;
        bottom++;
    }
}

static inline uint32_t perf_stack_peak(uint32_t caller_sp)
{
    const uint8_t *bottom = (const uint8_t *) VERUM_BENCH_STACK_BOTTOM_DEF;
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
