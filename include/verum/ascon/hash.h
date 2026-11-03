/**
 * @file      hash.h
 * @brief     Ascon-Hash256 cryptographic hash function.
 * @details   Deterministic, collision-resistant sponge hash operating over a 320-bit
 *            permutation state, absorbing padded messages in 64-bit rate blocks and
 *            squeezing a fixed 256-bit digest per NIST SP 800-232 Section 5.1.
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

#ifndef VERUM_ASCON_HASH_H_
#define VERUM_ASCON_HASH_H_

#include "standard/types.h"

/**
 * @brief      Ascon-Hash256 message digest (NIST SP 800-232 Section 5.1, Algorithm 5).
 * @details    Absorbs @p message_size bytes from @p message (or hashes the empty string
 *             when @p message_size is zero) and writes the 256-bit digest as eight
 *             consecutive 32-bit words into @p digest.
 *
 * @warning    @p message (when @p message_size >= 8) and @p digest must be 4-byte
 *             aligned; @p digest words are written in little-endian order.
 * @warning    @p message_size is in bytes rather than bits (@nonconformity NIST SP 800-232).
 *
 * @param[in]  message      Input message buffer (@c NULL permitted iff @p message_size == 0).
 * @param[in]  message_size Byte length of @p message (0 is valid).
 * @param[out] digest       Output buffer for the 256-bit digest (eight 32-bit LE words, 32 bytes).
 *
 * @pre        @p digest is non-NULL, 4-byte aligned, and does not overlap @p message.
 * @pre        When @p message_size > 0, @p message is non-NULL, addresses at least
 *             @p message_size readable bytes, and is 4-byte aligned when @p message_size >= 8.
 */

void VERUM_ASCON_HASH256_digest(const uint8_t *message,
                                uint32_t message_size,
                                uint32_t digest[8U]);

#endif // VERUM_ASCON_HASH_H_
