/**
 * @file      crt0.S
 * @brief     TriCore reset entry for the QEMU benchmark harness (GNU as syntax).
 * @details   Loads the user stack pointer (A10) and enters real_start() (startup.c).
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
    .section .startup_code, "ax", @progbits
    .global _start
    .type   _start, @function
_start:
    movh.a  %a10, hi:__stack_top
    lea     %a10, [%a10] lo:__stack_top
    j       real_start
    .size   _start, . - _start
