/**
 * @file       aead.h
 * @brief      NIST SP 800-232 ASCON AEAD-128A.
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
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 */
#include "verum/ascon/aead.h"
#include "standard/types.h"

/**
 * @ref NIST SP 800-232 Appendix B
 * @see https://doi.org/10.6028/NIST.SP.800-232
 */
static const uint32_t VERUM_ASCON_AEAD128_initialization_vector[2U] = {0x00001000UL, 0x808c0001UL};


void VERUM_ASCON_AEAD128_encrypt(const uint32_t        key[4U],
                                 const uint32_t        nonce[4U],
                                 const uint8_t * const data,
                                 const uint32_t plaintext_size,
                                 const uint32_t associated_size,)
{

}
