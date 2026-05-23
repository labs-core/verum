/**
 * @file      xof.h
 * @brief     Ascon Extendable-Output Function.
 * @details   This header declares the Ascon Extendable-Output Function.
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
#ifndef VERUM_ASCON_XOF_H_
#define VERUM_ASCON_XOF_H_

#include "standard/types.h"
#include "define.h"


/**
 * @brief      Ascon-XOF128 message digest.
 *
 * @details    Computes the hash of the input message using the
 *             Ascon-XOF128 algorithm as specified in NIST SP 800-232
 *             Section 5.1. The resulting digest is stored in the buffer
 *             pointed to by @p digest .
 *
 * @param[in]     message             Input message buffer.
 * @param[in]     message_size        Byte length of @p message.
 * @param[inout]  digest              Pointer to a buffer where the output digest will be stored. The buffer must be large enough to hold the desired output length in bits.
 */
void VERUM_ASCON_XOF128_digest(uint8_t *message,
                                uint32_t message_size,
                                uint32_t* digest,
                                const uint32_t digest_size_in_bits);


#endif // VERUM_ASCON_XOF_H_