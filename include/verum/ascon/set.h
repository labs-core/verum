/**
 * @file      set.h
 * @brief     Ascon feature-selection configuration macros.
 * @details   Compile-time configuration switches for Ascon public interfaces (NIST SP 800-232).
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
#ifndef VERUM_ASCON_SET_H_
#define VERUM_ASCON_SET_H_

#include "define.h"

/**
 * @defgroup VERUM_ASCON_AEAD128_feature_flags Ascon Feature Flags
 * @{
 */

#ifdef VERUM_CUSTOM_CONFIG
    #ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    #else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        #undef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    #endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

    #ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        #undef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    #endif /* VERUM_OPTIMIZATION_MEMORY_DEF */
#else /* VERUM_CUSTOM_CONFIG */
/**
 * @def     VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
 * @brief   Enable associated-data authentication in Ascon-AEAD128.
 * @details When defined, @c VERUM_ASCON_AEAD128_encrypt and @c VERUM_ASCON_AEAD128_decrypt
 *          accept @p associated_data and @p associated_size and authenticate that data
 *          (unencrypted) during tag generation. When undefined, both parameters, the
 *          16-byte AD staging buffer, and the Ascon-p[8] AD absorption phase are omitted.
 * @warning When defined, the AD absorption and padding phase executes unconditionally;
 *          undefine this macro when operating without associated data.
 */
    #undef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

/**
 * @def     VERUM_ASCON_BIT_INTERLEAVING_DEF
 * @brief   Enable bit-interleaved state representation for 32-bit platforms.
 * @details When defined, maps the 320-bit Ascon state to ten 32-bit words via the
 *          Boolean ring isomorphism \pi(S_w) = (E_w, O_w), separating even- and
 *          odd-indexed bits. In 32-bit architectures, this converts 64-bit cross-register
 *          rotations in the linear diffusion layer (p_L) into native 32-bit rotations
 *          (ROTR32) that fuse into single-cycle instructions on processors with a
 *          barrel shifter (e.g. ARM). Input and output blocks are converted via
 *          Morton delta-swap permutation networks.
 *          When undefined, the state is decomposed directly into low and high halves
 *          (L_w, H_w), eliminating Morton conversion overhead at the cost of cross-word
 *          funnel shifts in p_L.
 */
    #define VERUM_ASCON_BIT_INTERLEAVING_DEF

/**
 * @def     VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
 * @brief   Assume pre-interleaved secret key and nonce in Ascon-AEAD128.
 * @details Applicable only when @c VERUM_ASCON_BIT_INTERLEAVING_DEF is active.
 *          When defined, @c VERUM_ASCON_AEAD128_encrypt and @c VERUM_ASCON_AEAD128_decrypt
 *          expect the 128-bit secret key parameter @p key and 128-bit nonce parameter
 *          @p nonce to be already pre-interleaved into \pi(K) = (E_0, O_0, E_1, O_1)
 *          and \pi(N) = (E_2, O_2, E_3, O_3) by the caller (e.g., during session handshake
 *          or packet staging).
 *          This completely eliminates the runtime Morton interleaving of both key and
 *          nonce during initialization and tag computation for all subsequent messages.
 *          When undefined, @p key and @p nonce are accepted in standard little-endian format
 *          and converted to bit-interleaved form dynamically.
 * @warning When defined, passing raw little-endian keys or nonces will produce non-standard
 *          ciphertext and authentication tags.
 */
    #define VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    #ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    #else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        #undef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    #endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

/**
 * @def     VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
 * @brief   Enable full loop unrolling with fused round layers for maximum throughput.
 * @details When defined, the Ascon-p[12] and Ascon-p[8] permutations (@c VERUM_ASCON_PERMUTE_P12
 *          and @c VERUM_ASCON_PERMUTE_P8) expand into an unrolled sequence of fused inline
 *          register-pinned round macros (@c VERUM_ASCON_PERMUTE_SUBSTITUTION_LAYER,
 *          @c VERUM_ASCON_PERMUTE_MERGED, and @c VERUM_ASCON_PERMUTE_LINEAR_DIFFUSION_LAYER),
 *          trading program size (.text) for maximum speed.
 *          When undefined (or when @c VERUM_OPTIMIZATION_MEMORY_DEF is defined in define.h),
 *          the permutation is executed via the compact, shared, non-inlined subroutine
 *          @c VERUM_ASCON_permute, drastically reducing code footprint.
 */
    #define VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    #ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        #undef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    #endif /* VERUM_OPTIMIZATION_MEMORY_DEF */
#endif /* VERUM_CUSTOM_CONFIG */

/** @} */

#endif /* VERUM_ASCON_SET_H_ */
