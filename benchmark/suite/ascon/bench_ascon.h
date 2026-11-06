/**
 * @file      bench_ascon.h
 * @brief     Ascon-AEAD128 benchmark suite declaration.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_BENCH_ASCON_H_
#define VERUM_BENCH_ASCON_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Execute Ascon-AEAD128 benchmarks and print plain metrics.
 * @return 0 on success (KAT passed), non-zero on failure.
 */
int bench_ascon_run(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* VERUM_BENCH_ASCON_H_ */
