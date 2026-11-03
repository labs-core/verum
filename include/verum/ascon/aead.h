/**
 * @file      aead.h
 * @brief     Ascon-AEAD128 authenticated encryption.
 * @details   Authenticated Encryption with Associated Data (AEAD) guarantees plaintext
 *            confidentiality and tamper-evident authenticity of both plaintext and
 *            unencrypted associated data. Ascon-AEAD128 realises this via a 320-bit
 *            duplex sponge (128-bit rate, 128-bit key, 128-bit nonce) producing
 *            in-place ciphertext of equal length and a 128-bit authentication tag per
 *            NIST SP 800-232 Section 4.1.
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
#ifndef VERUM_ASCON_AEAD_H_
#define VERUM_ASCON_AEAD_H_

#include "standard/types.h"
#include "set.h"



/**
 * @brief         Ascon-AEAD128 authenticated encryption (NIST SP 800-232 Section 4.1.1, Algorithm 3).
 * @details       Encrypts @p plaintext in place and computes a 128-bit authentication tag
 *                over the ciphertext and, when @c VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
 *                is defined, @p associated_data. Overwrites @p plaintext with ciphertext
 *                of equal byte length.
 *
 * @warning       Nonce reuse under the same key breaks confidentiality and leaks key
 *                material; uniqueness per (key, plaintext) is the caller's responsibility.
 * @warning       The produced @p authentication_tag must be verified in constant time
 *                during decryption before any plaintext is released.
 * @warning       @p key, @p nonce, and @p authentication_tag must be little-endian 32-bit
 *                words; @p plaintext and @p associated_data must be 4-byte aligned.
 * @warning       Lengths (@p plaintext_size, @p associated_size) are in bytes rather than
 *                bits (@nonconformity NIST SP 800-232).
 *
 * @param[in]     key                128-bit secret key (four 32-bit LE words).
 * @param[in]     nonce              128-bit public nonce (four 32-bit LE words).
 * @param[in,out] plaintext          Entry: plaintext (@p plaintext_size bytes). Return: ciphertext in place.
 * @param[in]     plaintext_size     Byte length of @p plaintext (0 is valid; tag covers AD only).
 * @param[in]     associated_data    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Authenticated unencrypted AD buffer.
 * @param[in]     associated_size    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Byte length of @p associated_data.
 * @param[out]    authentication_tag 128-bit authentication tag (four 32-bit LE words, 16 bytes).
 *
 * @pre           @p key, @p nonce, @p plaintext, and @p authentication_tag are non-NULL and 4-byte aligned.
 * @pre           @p plaintext addresses at least @p plaintext_size writable bytes and does not overlap @p authentication_tag.
 * @pre           When AD is enabled, any non-NULL @p associated_data is 4-byte aligned.
 * @pre           @p nonce has not been previously used with @p key.
 */
void VERUM_ASCON_AEAD128_encrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint8_t        *plaintext,
                                 uint32_t plaintext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                 const uint8_t  * associated_data,
                                 uint32_t associated_size,
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
                                 uint32_t authentication_tag[4U]);

/**
 * @brief         Ascon-AEAD128 authenticated decryption (NIST SP 800-232 Section 4.1.2, Algorithm 4).
 * @details       Decrypts @p ciphertext in place and computes the candidate 128-bit
 *                authentication tag over the plaintext and, when
 *                @c VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF is defined, @p associated_data.
 *                Overwrites @p ciphertext with plaintext of equal byte length and writes
 *                the recomputed tag to @p authentication_tag.
 *
 * @warning       Outputs the recomputed candidate @p authentication_tag without comparing
 *                it; the caller must verify @p authentication_tag against the received tag
 *                in constant time before releasing or acting upon decrypted @p ciphertext.
 * @warning       @p key, @p nonce, and @p authentication_tag must be little-endian 32-bit
 *                words; @p ciphertext and @p associated_data must be 4-byte aligned.
 * @warning       Lengths (@p ciphertext_size, @p associated_size) are in bytes rather than
 *                bits (@nonconformity NIST SP 800-232).
 *
 * @param[in]     key                128-bit secret key (four 32-bit LE words).
 * @param[in]     nonce              128-bit public nonce matching encryption (four 32-bit LE words).
 * @param[in,out] ciphertext         Entry: ciphertext (@p ciphertext_size bytes). Return: plaintext in place.
 * @param[in]     ciphertext_size    Byte length of @p ciphertext (0 is valid; tag covers AD only).
 * @param[in]     associated_data    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Authenticated unencrypted AD buffer.
 * @param[in]     associated_size    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Byte length of @p associated_data.
 * @param[out]    authentication_tag Recomputed 128-bit candidate tag (four 32-bit LE words, 16 bytes).
 *
 * @pre           @p key, @p nonce, @p ciphertext, and @p authentication_tag are non-NULL and 4-byte aligned.
 * @pre           @p ciphertext addresses at least @p ciphertext_size writable bytes and does not overlap @p authentication_tag.
 * @pre           When AD is enabled, any non-NULL @p associated_data is 4-byte aligned.
 * @pre           @p nonce matches the nonce used during encryption.
 */
void VERUM_ASCON_AEAD128_decrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint8_t *ciphertext,
                                 uint32_t ciphertext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                 const uint8_t *associated_data,
                                 uint32_t associated_size,
#endif
                                 uint32_t authentication_tag[4U]);

#endif /* VERUM_ASCON_AEAD_H_ */
