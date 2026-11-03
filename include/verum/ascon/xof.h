/**
 * @file      xof.h
 * @brief     Ascon-XOF128 extendable-output function.
 * @details   Extendable-output sponge function (XOF) operating over a 320-bit
 *            permutation state, absorbing padded messages in 64-bit rate blocks and
 *            squeezing an arbitrary caller-specified byte length via iterated
 *            Ascon-p[12] permutations per NIST SP 800-232 Section 5.2.
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
#ifndef VERUM_ASCON_XOF_H_
#define VERUM_ASCON_XOF_H_

#include "standard/types.h"

/**
 * @brief        Ascon-XOF128 extendable-output digest (NIST SP 800-232 Section 5.2, Algorithm 6).
 * @details      Absorbs @p message_size bytes from @p message (or the empty string when
 *               @p message_size is zero) and squeezes @p digest_size bytes into @p digest.
 * @optimization Transfers full 64-bit rate blocks via 4-byte-aligned 32-bit word loads/stores
 *               and skips the final Ascon-p[12] permutation when @p digest_size is an exact
 *               multiple of 8 bytes.
 *
 * @warning      @p message (when @p message_size >= 8) and @p digest (when @p digest_size >= 8)
 *               must be 4-byte aligned; full 64-bit blocks are written as little-endian
 *               32-bit word pairs.
 * @warning      @p message_size and @p digest_size are in bytes rather than bits
 *               (@nonconformity NIST SP 800-232).
 *
 * @param[in]    message      Input message buffer (@c NULL permitted iff @p message_size == 0).
 * @param[in]    message_size Byte length of @p message (0 is valid).
 * @param[out]   digest       Output digest buffer of at least @p digest_size bytes.
 * @param[in]    digest_size  Desired output length in bytes (> 0).
 *
 * @pre          @p digest is non-NULL, @p digest_size > 0, and @p digest does not overlap @p message.
 * @pre          @p digest addresses at least @p digest_size writable bytes and is 4-byte
 *               aligned when @p digest_size >= 8.
 * @pre          When @p message_size > 0, @p message is non-NULL, addresses at least
 *               @p message_size readable bytes, and is 4-byte aligned when @p message_size >= 8.
 */
void VERUM_ASCON_XOF128_digest(const uint8_t  *message,
                               uint32_t message_size,
                               uint8_t  *digest,
                               uint32_t digest_size);

#endif /* VERUM_ASCON_XOF_H_ */
