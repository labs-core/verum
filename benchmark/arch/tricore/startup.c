/**
 * @file      startup.c
 * @brief     TriCore bare-metal C startup for the QEMU tricore_testboard harness.
 * @details   Initialises the context-save-area (CSA) free list, clears .bss and runs main().
 *            Not used when the benchmark is embedded in an AURIX Development Studio project,
 *            which already provides its own startup code.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */

#include "harness/semihost.h"
#include "standard/types.h"
#include "macro.h"

extern int main(void);
extern uint8_t __bss_start;
extern uint8_t __bss_end;
extern uint8_t __CSA_BEGIN;
extern uint8_t __CSA_COUNT;

#define VERUM_BENCH_CSA_BYTES 64U
#define VERUM_BENCH_CSFR_PCXI 0xFE00U
#define VERUM_BENCH_CSFR_FCX 0xFE38U

/* Freestanding runtime: written as plain byte loops, so GCC must not turn them back into calls to themselves. */
#define VERUM_BENCH_NO_LOOP_IDIOM __attribute__((optimize("no-tree-loop-distribute-patterns")))

void *memset(void *dest,
             int c,
             uint32_t n);
void *memcpy(void *dest,
             const void *src,
             uint32_t n);

VERUM_BENCH_NO_LOOP_IDIOM void *memset(void *dest,
                                       int c,
                                       uint32_t n)
{
    volatile uint8_t *d = (volatile uint8_t *) dest;
    for (uint32_t i = 0U; i < n; i++)
    {
        d[i] = (uint8_t) c;
    }
    return dest;
}

VERUM_BENCH_NO_LOOP_IDIOM void *memcpy(void *dest,
                                       const void *src,
                                       uint32_t n)
{
    volatile uint8_t *d = (volatile uint8_t *) dest;
    const volatile uint8_t *s = (const volatile uint8_t *) src;
    for (uint32_t i = 0U; i < n; i++)
    {
        d[i] = s[i];
    }
    return dest;
}

/* Links every 64-byte CSA into a free list: FCX -> CSA[0] -> CSA[1] -> ... -> 0.
 * Must be inlined: a CALL before FCX is valid has no context-save area and traps (seen at -O0). */
static inline __attribute__((always_inline)) void init_csa(void)
{
    const uint32_t csa_base = (uint32_t) &__CSA_BEGIN;
    const uint32_t csa_count = (uint32_t) &__CSA_COUNT;
    volatile uint32_t *csa = (volatile uint32_t *) csa_base;

    for (uint32_t i = 0U; i < (csa_count - 1U); i++)
    {
        uint32_t next = csa_base + ((i + 1U) * VERUM_BENCH_CSA_BYTES);
        /* CSA link word: segment = address[31:28], offset = address[21:6]. */
        csa[i * (VERUM_BENCH_CSA_BYTES / 4U)] = ((next >> 12U) & 0x000F0000U) | ((next >> 6U) & 0x0000FFFFU);
    }
    csa[(csa_count - 1U) * (VERUM_BENCH_CSA_BYTES / 4U)] = 0U;

    uint32_t first = ((csa_base >> 12U) & 0x000F0000U) | ((csa_base >> 6U) & 0x0000FFFFU);
    __asm__ volatile ("mtcr %0, %1\n\tisync" : : "i" (VERUM_BENCH_CSFR_PCXI), "d" (0U) : "memory");
    __asm__ volatile ("mtcr %0, %1\n\tisync" : : "i" (VERUM_BENCH_CSFR_FCX), "d" (first) : "memory");
}

VERUM_ATTR_NORETURN __attribute__((used)) void real_start(void);
VERUM_ATTR_NORETURN void real_start(void)
{
    init_csa();

    for (volatile uint8_t *bss_byte = &__bss_start; bss_byte < &__bss_end; bss_byte++)
    {
        *bss_byte = 0U;
    }

    int rc = main();
    semihost_exit((uint32_t) rc);
    for (;;)
    {
    }
}
