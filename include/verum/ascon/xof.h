/**
 * @file      xof.h
 * @brief     Ascon-XOF128 extendable-output function.
 * @details   An extendable-output function (XOF) generalises a hash function by
 *            allowing the caller to request a digest of any desired byte length
 *            rather than a fixed-size output. ASCON-XOF128 realises this
 *            construction through a sponge operating over a 320-bit permutation
 *            state, absorbing the padded message in 64-bit rate blocks and
 *            squeezing an arbitrary number of output bytes through repeated
 *            applications of the Ascon-p permutation, as standardised in
 *            NIST SP 800-232.
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
#include "define.h"

/**
 * @brief      Ascon-XOF128 extendable-output digest.
 *
 * @details    Computes @p digest_size bytes of output from @p message using the
 *             Ascon-XOF128 sponge construction defined in Algorithm 9 of NIST
 *             SP 800-232 Section 5.2.
 *
 * @param[in]  message         Input message buffer. May be @c NULL if and only
 *                             if @p message_size is zero, in which case the XOF
 *                             output over the empty string is produced.
 * @param[in]  message_size    Byte length of @p message. May be zero.
 * @param[out] digest          Destination buffer for the output digest. The
 *                             caller is responsible for providing a buffer of at
 *                             least @p digest_size bytes.
 * @param[in]  digest_size     Desired output length in bytes. Must be greater
 *                             than zero.
 *
 * @pre        @p digest is non-NULL.
 * @pre        @p message is non-NULL when @p message_size is greater than zero.
 * @pre        @p message points to a readable buffer of at least @p message_size bytes.
 * @pre        @p digest points to a writable buffer of at least @p digest_size bytes.
 * @pre        @p digest_size is greater than zero.
 * @pre        @p message and @p digest do not overlap.
 *
 */
void VERUM_ASCON_XOF128_digest(uint8_t  *message,
                               uint32_t  message_size,
                               uint8_t  *digest,
                               uint32_t  digest_size);

#endif /* VERUM_ASCON_XOF_H_ */