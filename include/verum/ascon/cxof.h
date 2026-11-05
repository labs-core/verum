/**
 * @file      cxof.h
 * @brief     Ascon-CXOF128 customizable extendable-output function.
 * @details   Customizable extendable-output sponge function (CXOF) operating over a 320-bit
 *            permutation state, absorbing a length-prefixed, padded customization string Z
 *            (up to 2048 bits / 256 bytes) and padded messages in 64-bit rate blocks, and
 *            squeezing an arbitrary caller-specified byte length via iterated
 *            Ascon-p[12] permutations per NIST SP 800-232 Section 5.3.
 *
 * @see       https://doi.org/10.6028/NIST.SP.800-232
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_ASCON_CXOF_H_
#define VERUM_ASCON_CXOF_H_

#include "standard/types.h"

/**
 * @brief      Ascon-CXOF128 customizable extendable-output digest (NIST SP 800-232 Section 5.3, Algorithm 7).
 * @details    Absorbs @p customization_size bytes of domain-separation string from @p customization,
 *             absorbs @p message_size bytes from @p message (or the empty string when
 *             @p message_size is zero), and squeezes @p digest_size bytes into @p digest.
 *
 * @warning    @p message (when @p message_size >= 8), @p customization (when @p customization_size >= 8),
 *             and @p digest (when @p digest_size >= 8) must be 4-byte aligned; full 64-bit blocks
 *             are written as little-endian 32-bit word pairs.
 * @warning    @p message_size, @p customization_size, and @p digest_size are in bytes rather than bits
 *             (@nonconformity NIST SP 800-232).
 * @warning    Per NIST SP 800-232 Section 5.3, the customization string bit-length must satisfy
 *             |Z| <= 2048 bits (@p customization_size <= 256 bytes).
 *
 * @param[in]  message            Input message buffer (@c NULL permitted iff @p message_size == 0).
 * @param[in]  message_size       Byte length of @p message (0 is valid).
 * @param[in]  customization      Input customization buffer (@c NULL permitted iff @p customization_size == 0).
 * @param[in]  customization_size Byte length of @p customization (0 <= customization_size <= 256).
 * @param[out] digest             Output digest buffer of at least @p digest_size bytes.
 * @param[in]  digest_size        Desired output length in bytes (> 0).
 *
 * @pre        @p digest is non-NULL, @p digest_size > 0, and @p digest does not overlap @p message or @p customization.
 * @pre        @p digest addresses at least @p digest_size writable bytes and is 4-byte
 *             aligned when @p digest_size >= 8.
 * @pre        When @p message_size > 0, @p message is non-NULL, addresses at least
 *             @p message_size readable bytes, and is 4-byte aligned when @p message_size >= 8.
 * @pre        When @p customization_size > 0, @p customization is non-NULL, addresses at least
 *             @p customization_size readable bytes, is 4-byte aligned when @p customization_size >= 8,
 *             and @p customization_size <= 256.
 */
void VERUM_ASCON_CXOF128_digest(const uint8_t  *message,
                                uint32_t message_size,
                                const uint8_t  *customization,
                                uint32_t customization_size,
                                uint8_t  *digest,
                                uint32_t digest_size);

#endif /* VERUM_ASCON_CXOF_H_ */
