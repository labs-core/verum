#ifndef VERUM_ASCON_AEAD_H_
#define VERUM_ASCON_AEAD_H_

#include "standard/types.h"

void VERUM_ASCON_AEAD128_encrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint32_t state[10U],
                                 const uint8_t * const data,
                                 const uint32_t plaintext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA
                                 const uint32_t associated_size,
#endif
                                 uint32_t const authentication_tag[4U]);

#endif