/**
 * @file      verify.h
 * @brief     LM-OTS one-time signature verification.
 * @details    Leighton-Micali One-Time Signatures (LM-OTS) are a hash-based
 *             one-time signature scheme underlying the Leighton-Micali
 *             Signature (LMS) system, one of the two stateful hash-based
 *             signature schemes approved by NIST for post-quantum
 *             transitional use. Verification recomputes a candidate public
 *             key from the message, signature, and the claimed public key's
 *             parameters, then compares it against the public key provided
 *             by the verifier. No private key material is required or
 *             produced by this operation, as standardised in RFC 8554
 *             Section 4.6 and profiled for approved parameter sets in
 *             NIST SP 800-208.
 *
 * @see       https://www.rfc-editor.org/rfc/rfc8554
 * @see       https://www.rfc-editor.org/rfc/rfc9858
 * @see       https://doi.org/10.6028/NIST.SP.800-208
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_LEIGHTON_MICALI_OTS_VERIFY_H_
#define VERUM_LEIGHTON_MICALI_OTS_VERIFY_H_

#include "standard/types.h"
#include "define.h"


/**
 * @brief      LM-OTS one-time signature verification.
 *
 * @details    Recomputes a candidate public key from @p message and
 *             @p signature by iterating each of the @p p Winternitz hash
 *             chains to their final position, then hashes the resulting
 *             chain values together with @p identifier and @p leaf_index
 *             to form a candidate value. The operation follows Algorithm 4b
 *             of RFC 8554 Section 4.6.
 *
 * @param[in]  identifier            16-byte identifier @c I of the LMS
 *                                   private key this one-time key
 *                                   belongs to.
 * @param[in]  leaf_index            4-byte leaf number @c q of this
 *                                   one-time key within the LMS tree.
 * @param[in]  message               Pointer to the message that was
 *                                   signed, @p message_size bytes.
 * @param[in]  message_size          Length of @p message in bytes.
 * @param[in]  signature             LM-OTS signature to verify,
 *                                   consisting of the typecode, the
 *                                   @c n-byte randomizer @c C, and the
 *                                   @c p chain values @c y, each
 *                                   @c n bytes, per RFC 8554 Section 4.4.
 * @param[in]  signature_size        Length of @p signature in bytes.
 *                                   Must equal the fixed size implied
 *                                   by @p lmots_type; a mismatch is
 *                                   treated as verification failure
 *                                   rather than undefined behaviour.
 * @param[in]  public_key_candidate            Claimed LM-OTS public key, consisting
 *                                   of the @c n-byte randomizer @c C and the
 *                                   @c p chain values @c y, each @c n bytes,
 *                                   per RFC 8554 Section 4.4.
 *
 * @pre        @p identifier, @p public_key_candidate, @p message, and @p signature
 *             are non-NULL.
 * @pre        @p signature_size matches the length implied by
 *             ::VERUM_LEIGHTON_MICALI_OTS_TYPE. 
 *
 * @see       https://www.rfc-editor.org/rfc/rfc8554
 * @see       https://www.rfc-editor.org/rfc/rfc9858
 * @see       https://doi.org/10.6028/NIST.SP.800-208
 *
 */
void VERUM_LEIGHTON_MICALI_OTS_verify(const uint8_t identifier[16U],
                                               uint32_t leaf_index,
                                               const uint8_t *public_key_candidate,
                                               const uint8_t *message,
                                               uint32_t message_size,
                                               const uint8_t *signature,
                                               uint32_t signature_size
                                               );


#endif /* VERUM_LEIGHTON_MICALI_OTS_VERIFY_H_ */