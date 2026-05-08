#include "auxiliary/memory.h"
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
__attribute__((noinline))
void VERUM_AUX_MEMORY_copy128(void * restrict destination,
                              const void * restrict source)
{
    uint32_t *const d = (uint32_t *) __builtin_assume_aligned(destination, sizeof(uint32_t));
    const uint32_t *const s = (const uint32_t *) __builtin_assume_aligned(source, sizeof(uint32_t));

    d[0U] = s[0U];
    d[1U] = s[1U];
    d[2U] = s[2U];
    d[3U] = s[3U];
}
