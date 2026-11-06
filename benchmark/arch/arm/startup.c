/**
 * @file      startup.c
 * @brief     ARM Cortex-M4 bare-metal startup and semihosting implementation.
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
void Reset_Handler(void);

__attribute__((section(".vectors"), used))
const void * const g_pfnVectors[] = {
    &__stack_top,
    (const void *) Reset_Handler
};

/* --- EABI Low-Level Memory Helpers for Freestanding Builds --- */
void __aeabi_memclr4(void *dest,
                     uint32_t n);
void __aeabi_memclr8(void *dest,
                     uint32_t n);
void __aeabi_memclr(void *dest,
                    uint32_t n);
void __aeabi_memset(void *dest,
                    uint32_t n,
                    int c);
void __aeabi_memcpy(void *dest,
                    const void *src,
                    uint32_t n);
void __aeabi_memcpy4(void *dest,
                     const void *src,
                     uint32_t n);
void __aeabi_memcpy8(void *dest,
                     const void *src,
                     uint32_t n);
void *memset(void *dest,
             int c,
             uint32_t n);
void *memcpy(void *dest,
             const void *src,
             uint32_t n);

void __aeabi_memclr4(void *dest,
                     uint32_t n)
{
    uint32_t *d = (uint32_t *) dest;
    while (n >= 4U)
    {
        *d = 0U;
        d++;
        n -= 4U;
    }
    uint8_t *d8 = (uint8_t *) d;
    while (n > 0U)
    {
        *d8 = 0U;
        d8++;
        n--;
    }
}

void __aeabi_memclr8(void *dest,
                     uint32_t n)
{
    __aeabi_memclr4(dest, n);
}

void __aeabi_memclr(void *dest,
                    uint32_t n)
{
    __aeabi_memclr4(dest, n);
}

void __aeabi_memset(void *dest,
                    uint32_t n,
                    int c)
{
    uint8_t *d = (uint8_t *) dest;
    while (n > 0U)
    {
        *d = (uint8_t) c;
        d++;
        n--;
    }
}

void __aeabi_memcpy(void *dest,
                    const void *src,
                    uint32_t n)
{
    uint8_t *d = (uint8_t *) dest;
    const uint8_t *s = (const uint8_t *) src;
    while (n > 0U)
    {
        *d = *s;
        d++;
        s++;
        n--;
    }
}

void __aeabi_memcpy4(void *dest,
                     const void *src,
                     uint32_t n)
{
    __aeabi_memcpy(dest, src, n);
}

void __aeabi_memcpy8(void *dest,
                     const void *src,
                     uint32_t n)
{
    __aeabi_memcpy(dest, src, n);
}

void *memset(void *dest,
             int c,
             uint32_t n)
{
    __aeabi_memset(dest, n, c);
    return dest;
}

void *memcpy(void *dest,
             const void *src,
             uint32_t n)
{
    __aeabi_memcpy(dest, src, n);
    return dest;
}

static uint32_t arm_semihost(uint32_t op,
                             const void *arg)
{
    register uint32_t r0 __asm__ ("r0") = op;
    register const void *r1 __asm__ ("r1") = arg;
    __asm__ volatile ("bkpt 0xAB" : "+r" (r0) : "r" (r1) : "memory");
    return r0;
}

void semihost_puts(const char *str)
{
    (void) arm_semihost(0x04U, str);
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
    (void) arm_semihost(0x20U, block);
    for (;;)
    {
        __asm__ volatile ("wfi");
    }
}

void Reset_Handler(void)
{
    perf_init();
    int rc = main();
    semihost_exit((uint32_t) rc);
}
