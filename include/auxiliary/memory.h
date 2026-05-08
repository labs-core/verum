/**
 * @file      memory.h
 * @brief     Auxiliary memory operations.
 * @details   This header declares auxiliary memory operations to promote
 *            consistency and portability without depending on the
 *            C standard library. It also enables aliasing between types
 *            on other projects that may want to use VERUM.
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 */
#ifndef VERUM_AUX_MEMORY_H_
#define VERUM_AUX_MEMORY_H_

#include "standard/types.h"

/**
 * @brief      Copy exactly 128 bits (16 bytes) from @p source to @p destination.
 *
 * @details    Fixed-width specialisation for 128-bit block transfers.
 *             Both pointers must be 4-byte aligned and must not overlap.
 *             Emits exactly four word-width loads and four word-width stores
 *             with no branching or runtime alignment probing.
 *
 * @param[out] destination  Target buffer.  Must be 4-byte aligned.
 *                          Must not overlap @p source.
 * @param[in]  source       Source buffer.  Must be 4-byte aligned.
 *                          Must not overlap @p destination.
 *
 * @pre        @p destination and @p source are non-NULL.
 * @pre        Both pointers are aligned to @c sizeof(uint32_t).
 * @pre        The regions [@p destination, @p destination + 16) and
 *             [@p source, @p source + 16) do not overlap.
 */
void VERUM_AUX_MEMORY_copy128(void * restrict destination,
                              const void * restrict source);

#endif /* VERUM_AUX_MEMORY_H_ */
