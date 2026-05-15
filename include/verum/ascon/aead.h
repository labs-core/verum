/**
 * @file      ascon_aead.h
 * @brief     Ascon-AEAD128 authenticated encryption.
 * @details    Authenticated Encryption with Associated Data (AEAD) is a form of
 *             encryption that simultaneously guarantees confidentiality of the
 *             plaintext and authenticity of both the plaintext and the associated
 *             data. Associated data is authenticated but not encrypted,tamper-evident.
 *             ASCON-AEAD128 realises this construction through a
 *             duplex sponge operating over a 320-bit permutation state, binding a
 *             128-bit key and a 128-bit nonce to produce a ciphertext equal in
 *             length to the plaintext and a 128-bit authentication tag, as
 *             standardised in NIST SP 800-232.
 *
 * @see       https://doi.org/10.6028/NIST.SP.800-232
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 */
#ifndef VERUM_ASCON_AEAD_H_
#define VERUM_ASCON_AEAD_H_

#include "standard/types.h"
#include "define.h"

#undef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF


/**
 * @brief      Ascon-AEAD128 authenticated encryption.
 *
 * @details    Encrypts @p plaintext in place and produces a 128-bit
 *             authentication tag over the ciphertext and, when
 *             @c VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF is defined,
 *             over @p associated_data as well. The operation follows
 *             Algorithm 3 of NIST SP 800-232 Section 4.1.1.
 *
 *             On return, the buffer addressed by @p plaintext holds the
 *             ciphertext of equal length. The original plaintext is
 *             overwritten and cannot be recovered from @p plaintext alone.
 *
 * @param[in]  key                128-bit secret key as four consecutive
 *                                32-bit words. Must remain valid for the
 *                                duration of the call.
 * @param[in]  nonce              128-bit public nonce as four consecutive
 *                                32-bit words. Must be unique per
 *                                (key, plaintext) pair.
 * @param[in,out] state           320-bit Ascon permutation state as ten
 *                                consecutive 32-bit words. Initialised
 *                                internally; caller storage must be
 *                                provided but need not be pre-filled.
 * @param[in,out] plaintext       On entry: plaintext buffer of
 *                                @p plaintext_size bytes.
 *                                On return: ciphertext of equal length,
 *                                written in place.
 * @param[in]  plaintext_size     Length of @p plaintext in bytes.
 *                                May be zero, in which case no plaintext
 *                                blocks are processed and the tag covers
 *                                only associated data.
 *
 * @param[in]  associated_data    Pointer to associated data of
 *                                @p associated_size bytes. Authenticated
 *                                but not encrypted. Only present when
 *                                @c VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
 *                                is defined.
 * @param[in]  associated_size    Length of @p associated_data in bytes.
 *                                May be zero. Only present when
 *                                @c VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
 *                                is defined.
 *
 * @param[out] authentication_tag 128-bit authentication tag produced
 *                                after finalisation, written as four
 *                                consecutive 32-bit words.
 *
 * @pre        @p key, @p nonce, @p state, @p plaintext and
 *             @p authentication_tag are non-NULL.
 * @pre        @p plaintext points to a buffer of at least
 *             @p plaintext_size bytes.
 * @pre        @p plaintext and @p authentication_tag do not overlap.
 * @pre        The nonce is used at most once for a given key.
 *
 */
void VERUM_ASCON_AEAD128_encrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint32_t state[10U],
                                 uint8_t        *plaintext,
                                 const uint32_t plaintext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                 const uint8_t  * associated_data,
                                 const uint32_t associated_size,
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
                                 uint32_t authentication_tag[4U]);

void VERUM_ASCON_AEAD128_decrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint32_t state[10U],
                                 uint8_t *ciphertext,
                                 const uint32_t ciphertext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                 const uint8_t *associated_data,
                                 const uint32_t associated_size,
#endif
                                 uint32_t authentication_tag[4U]);

#endif /* VERUM_ASCON_AEAD_H_ */
