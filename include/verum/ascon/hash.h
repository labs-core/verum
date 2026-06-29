/**
 * @file      hash.h
 * @brief     Ascon-Hash256 cryptographic hash function.
 * @details   A cryptographic hash function maps an arbitrary-length message to a
 *            fixed-length digest in a deterministic and collision-resistant manner.
 *            ASCON-Hash256 realises this construction through a sponge operating
 *            over a 320-bit permutation state, absorbing the padded message in
 *            64-bit rate blocks and squeezing a 256-bit digest, as standardised
 *            in NIST SP 800-232.
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
#include "define.h"

/**
 * @brief      Ascon-Hash256 message digest.
 *
 * @details    Computes the 256-bit digest of @p message using the Ascon-Hash256
 *             sponge construction defined in Algorithm 7 of NIST SP 800-232
 *             Section 5.1.
 *
 * @param[in]  message         Input message buffer. May be @c NULL if and only
 *                             if @p message_size is zero, in which case the hash
 *                             of the empty string is computed.
 * @param[in]  message_size    Byte length of @p message. May be zero.
 * @param[out] digest          Destination buffer for the 256-bit digest, written
 *                             as eight consecutive 32-bit words. The caller is
 *                             responsible for providing a buffer of at least
 *                             eight words.
 *
 * @pre        @p digest is non-NULL.
 * @pre        @p message is non-NULL when @p message_size is greater than zero.
 * @pre        @p message points to a readable buffer of at least @p message_size bytes.
 * @pre        @p message and @p digest do not overlap.
 *
 */

void VERUM_ASCON_HASH256_digest(uint8_t *message,
                                uint32_t message_size,
                                uint32_t digest[8U]);

#endif // VERUM_ASCON_HASH_H_
