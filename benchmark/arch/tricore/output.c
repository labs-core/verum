/**
 * @file      output.c
 * @brief     TriCore implementation of the benchmark text-output interface (harness/semihost.h).
 * @details   Two back-ends, selected at build time:
 *
 *            VERUM_TRICORE_QEMU_DEF defined   QEMU tricore_testboard test device. Every character
 *                                             is emitted as a write to 0xF1000000 + char and the
 *                                             exit code is written to 0xF0000000.
 *            VERUM_TRICORE_QEMU_DEF undefined Real silicon / AURIX simulator in AURIX Development
 *                                             Studio. Characters go through the weak hook
 *                                             verum_bench_putc() (override it to drive an ASCLIN
 *                                             UART) and are always mirrored into the RAM log
 *                                             verum_bench_log[], which can be read from the debugger.
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

#ifdef VERUM_TRICORE_QEMU_DEF

#define VERUM_BENCH_QEMU_CHAR_BASE 0xF1000000U
#define VERUM_BENCH_QEMU_EXIT_ADDR 0xF0000000U

static void bench_putc(char c)
{
    *(volatile uint8_t *) (VERUM_BENCH_QEMU_CHAR_BASE + (uint32_t) (uint8_t) c) = 0U;
}

#else /* VERUM_TRICORE_QEMU_DEF */

#ifndef VERUM_BENCH_LOG_SIZE_DEF
#define VERUM_BENCH_LOG_SIZE_DEF 4096U
#endif /* VERUM_BENCH_LOG_SIZE_DEF */

/** NUL-terminated benchmark transcript, readable from the debugger (symbol verum_bench_log). */
char verum_bench_log[VERUM_BENCH_LOG_SIZE_DEF];
volatile uint32_t verum_bench_log_length = 0U;
volatile uint32_t verum_bench_exit_code = 0xFFFFFFFFU;

/** Weak transmit hook: override to forward characters to a UART. Default is a no-op. */
__attribute__((weak)) void verum_bench_putc(char c);
__attribute__((weak)) void verum_bench_putc(char c)
{
    (void) c;
}

static void bench_putc(char c)
{
    uint32_t n = verum_bench_log_length;
    if (n < (VERUM_BENCH_LOG_SIZE_DEF - 1U))
    {
        verum_bench_log[n] = c;
        verum_bench_log[n + 1U] = '\0';
        verum_bench_log_length = n + 1U;
    }
    verum_bench_putc(c);
}

#endif /* VERUM_TRICORE_QEMU_DEF */

void semihost_puts(const char *str)
{
    if (str == ((void *) 0))
    {
        return;
    }
    while (*str != '\0')
    {
        bench_putc(*str);
        str++;
    }
}

void semihost_put_u32(uint32_t value)
{
    char buf[12U];
    uint32_t idx = 0U;
    uint32_t v = value;

    if (v == 0U)
    {
        buf[idx] = '0';
        idx++;
    }
    else
    {
        char rev[12U];
        uint32_t rev_idx = 0U;
        while (v > 0U)
        {
            rev[rev_idx] = (char) ('0' + (v % 10U));
            rev_idx++;
            v /= 10U;
        }
        while (rev_idx > 0U)
        {
            rev_idx--;
            buf[idx] = rev[rev_idx];
            idx++;
        }
    }
    buf[idx] = '\0';
    semihost_puts(buf);
}

void semihost_put_fixed2(uint32_t num,
                         uint32_t den)
{
    if (den == 0U)
    {
        semihost_puts("0.00");
        return;
    }
    uint32_t integer_part = num / den;
    uint32_t frac_part = ((num % den) * 100U) / den;

    semihost_put_u32(integer_part);
    semihost_puts(".");
    if (frac_part < 10U)
    {
        semihost_puts("0");
    }
    semihost_put_u32(frac_part);
}

void semihost_exit(uint32_t code)
{
#ifdef VERUM_TRICORE_QEMU_DEF
    *(volatile uint32_t *) VERUM_BENCH_QEMU_EXIT_ADDR = code;
    for (;;)
    {
    }
#else /* VERUM_TRICORE_QEMU_DEF */
    verum_bench_exit_code = code; /* breakpoint here: results are in verum_bench_log */
    for (;;)
    {
        __asm__ volatile ("debug");
    }
#endif /* VERUM_TRICORE_QEMU_DEF */
}
