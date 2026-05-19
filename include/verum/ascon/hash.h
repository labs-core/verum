/**
 * @file      hash.h
 * @brief     Ascon Hashing Algorithm.
 * @details   This header declares the Ascon Hashing Algorithm.
 *
 * @see       https://doi.org/10.6028/NIST.SP.800-232
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_ASCON_HASH_H_
#define VERUM_ASCON_HASH_H_

#include "standard/types.h"
#include "define.h"

/**
 * @brief      Ascon-Hash256 message digest.
 *
 * @details    Computes the 256-bit hash of the input message using the
 *             Ascon-Hash256 algorithm as specified in NIST SP 800-232
 *             Section 5.1. The resulting digest is stored in the buffer
 *             pointed to by @p digest as eight 32-bit words.
 *
 * @param[in]     message             Input message buffer.
 * @param[in]     message_size        Byte length of @p message.
 * @param[inout]  digest              256-bit message digest as eight 32-bit words.
 */
void VERUM_ASCON_HASH256_digest(uint8_t *message,
                                uint32_t message_size,
                                uint32_t digest[8U]);

#endif // VERUM_ASCON_HASH_H_
