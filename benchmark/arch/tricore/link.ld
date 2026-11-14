/**
 * @file      link.ld
 * @brief     Linker script for the TriCore GCC benchmark on QEMU tricore_testboard.
 * @details   TC1.6.2 (TC37x class core). Code and read-only data live in the 0x80000000
 *            (cached program flash alias) region; data, bss and the user stack live in
 *            the 0xA1000000 RAM region; the CSA pool lives in 0xD0000000.
 *            This script is for the QEMU harness only. On real silicon inside AURIX
 *            Development Studio use the project's own linker script and see README.md.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */

ENTRY(_start)

MEMORY
{
    text_ram (rx)  : ORIGIN = 0x80000000, LENGTH = 2M
    csa_ram  (w!x) : ORIGIN = 0xd0000000, LENGTH = 48K
    data_ram (w!x) : ORIGIN = 0xa1000000, LENGTH = 4M
}

__CSA_BEGIN = 0xd0000000;
__CSA_COUNT = 128;

SECTIONS
{
    .text :
    {
        KEEP(*(.startup_code))
        *(.text .text.*)
        . = ALIGN(8);
    } > text_ram

    .rodata :
    {
        *(.rodata .rodata.*)
        . = ALIGN(8);
    } > text_ram

    .data :
    {
        *(.data .data.* .sdata .sdata.* .zdata .zdata.* .bdata .bdata.*)
        . = ALIGN(8);
    } > data_ram

    .bss (NOLOAD) :
    {
        __bss_start = .;
        *(.bss .bss.* .sbss .sbss.* .zbss .zbss.* .bbss .bbss.* COMMON)
        . = ALIGN(8);
        __bss_end = .;
    } > data_ram

    /* 32 KiB user stack at the top of the first 64 KiB of data RAM. Painted by perf.h. */
    __stack_bottom = 0xa1008000;
    __stack_top    = 0xa1010000;

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
    }
}
