/**
 * @file      startup.c
 * @brief     RISC-V 32 bare-metal startup and semihosting implementation.
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
#include "harness/perf.h"

extern int main(void);

void *memset(void *dest,
             int c,
             uint32_t n);
void *memcpy(void *dest,
             const void *src,
             uint32_t n);

void *memset(void *dest,
             int c,
             uint32_t n)
{
    uint8_t *d = (uint8_t *) dest;
    for (uint32_t i = 0U; i < n; i++)
    {
        d[i] = (uint8_t) c;
    }
    return dest;
}

void *memcpy(void *dest,
             const void *src,
             uint32_t n)
{
    uint8_t *d = (uint8_t *) dest;
    const uint8_t *s = (const uint8_t *) src;
    for (uint32_t i = 0U; i < n; i++)
    {
        d[i] = s[i];
    }
    return dest;
}

__attribute__((naked, section(".text.start"))) void _start(void)
{
    __asm__ volatile (
        "la sp, __stack_top\n"
        "call main\n"
        "mv a0, a0\n"
        "call semihost_exit\n"
        "1: wfi\n"
        "j 1b\n"
        );
}

static uint32_t riscv_semihost(uint32_t op,
                               const void *arg)
{
    register uint32_t a0 __asm__ ("a0") = op;
    register const void *a1 __asm__ ("a1") = arg;
    __asm__ volatile (
        ".balign 16\n"
        ".option push\n"
        ".option norvc\n"
        "slli zero, zero, 0x1f\n"
        "ebreak\n"
        "srai zero, zero, 7\n"
        ".option pop\n"
        : "+r" (a0) : "r" (a1) : "memory");
    return a0;
}

void semihost_puts(const char *str)
{
    (void) riscv_semihost(0x04U, str);
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
    static uint32_t block[2U];
    block[0U] = 0x20026U; /* ApplicationExit */
    block[1U] = code;
    (void) riscv_semihost(0x20U, block);
    for (;;)
    {
        __asm__ volatile ("wfi");
    }
}
