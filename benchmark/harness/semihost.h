/**
 * @file      semihost.h
 * @brief     Semihosting interface for bare-metal target benchmark runners.
 * @details   Provides character/string output and program exit using standard
 *            ARM and RISC-V semihosting trap instructions.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_BENCH_SEMIHOST_H_
#define VERUM_BENCH_SEMIHOST_H_

#include "standard/types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief  Transmit a NUL-terminated string to host stdout via semihosting.
 * @param  str String buffer to write.
 */
void semihost_puts(const char *str);

/**
 * @brief  Transmit an unsigned 32-bit integer formatted as decimal text.
 * @param  value Value to write.
 */
void semihost_put_u32(uint32_t value);

/**
 * @brief  Transmit a fixed-point decimal quotient (num / den) with 2 decimal places.
 * @param  num Numerator.
 * @param  den Denominator (must be > 0).
 */
void semihost_put_fixed2(uint32_t num,
                         uint32_t den);

/**
 * @brief  Exit the QEMU emulator session with a status code.
 * @param  code Exit code (0 for success).
 */
void semihost_exit(uint32_t code);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* VERUM_BENCH_SEMIHOST_H_ */
