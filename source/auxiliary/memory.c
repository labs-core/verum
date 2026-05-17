/**
 * @file       memory.c
 * @brief      Memory primitives.
 * @details    Defines fixed-size memory operations optimized for 32-bit embedded
 *             targets, using explicit aligned word accesses to preserve predictable
 *             instruction generation and bounded code footprint.
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 */

#include "auxiliary/memory.h"
#include "define.h"
#include "standard/types.h"

/**
 * @internal
 * @brief Copies 128 bits (16 bytes) from @p source to @p destination.
 *
 * @details
 * Both pointers are asserted word-aligned via @c __builtin_assume_aligned,
 * allowing the compiler to emit four aligned word stores.
 *
 * @c noinline is applied so the four stores are not duplicated at every
 * call site when optimisation is enabled, keeping the instruction cache
 * footprint predictable in constrained targets.
 *
 * @param[out] destination  4-byte aligned target buffer of at least 16 bytes.
 * @param[in]  source       4-byte aligned source buffer of at least 16 bytes.
 */
VERUM_ATTR_NOINLINE
void VERUM_AUX_MEMORY_16B_copy(void * restrict destination,
                               const void * restrict source)
{
    uint32_t *const dest = (uint32_t *) __builtin_assume_aligned(destination, sizeof(uint32_t));
    const uint32_t *const src = (const uint32_t *) __builtin_assume_aligned(source, sizeof(uint32_t));

    dest[0U] = src[0U];
    dest[1U] = src[1U];
    dest[2U] = src[2U];
    dest[3U] = src[3U];
}
