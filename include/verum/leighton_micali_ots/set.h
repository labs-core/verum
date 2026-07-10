/**
 * @file      set.h
 * @brief     LM-OTS parameter set configuration.
 * @details   Declares the compile-time LM-OTS parameter set selection macro
 *            and enumerates all valid LM-OTS typecodes defined in RFC 8554
 *            Section 9.1. This configuration determines the hash function and
 *            Winternitz parameters used throughout the library.
 *
 * @see       https://www.rfc-editor.org/rfc/rfc8554
 * @see       https://www.rfc-editor.org/rfc/rfc9858
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_LEIGHTON_MICALI_OTS_SET_H_
#define VERUM_LEIGHTON_MICALI_OTS_SET_H_

#include "standard/types.h"

/**
 * @enum VERUM_LEIGHTON_MICALI_OTS_typecode
 * @brief Valid LM-OTS typecodes per RFC 8554 Section 9.1.
 *
 * @details Enumerates the standardised LM-OTS parameter sets defined by the
 *          IANA LM-OTS Typecode Registry. Each typecode encodes a hash
 *          function and Winternitz parameter (@c w), which determine @c n, @c p,
 *          and @c ls as specified in RFC 8554 Section 2.
 *
 * @see     https://www.rfc-editor.org/rfc/rfc8554#section-9.1
 * @see     https://www.iana.org/assignments/leighton-micali-signatures/
 */
typedef enum {
    VERUM_LEIGHTON_MICALI_OTS_SHA256_N32_W1   = 0x00000001U,  /**< SHA256, n=32, w=1  */
    VERUM_LEIGHTON_MICALI_OTS_SHA256_N32_W2   = 0x00000002U,  /**< SHA256, n=32, w=2  */
    VERUM_LEIGHTON_MICALI_OTS_SHA256_N32_W4   = 0x00000004U,  /**< SHA256, n=32, w=4  */
    VERUM_LEIGHTON_MICALI_OTS_SHA256_N32_W8   = 0x00000008U,  /**< SHA256, n=32, w=8  */
    VERUM_LEIGHTON_MICALI_OTS_SHAKE256_N32_W1 = 0x00000011U,  /**< SHAKE256, n=32, w=1  */
    VERUM_LEIGHTON_MICALI_OTS_SHAKE256_N32_W2 = 0x00000012U,  /**< SHAKE256, n=32, w=2  */
    VERUM_LEIGHTON_MICALI_OTS_SHAKE256_N32_W4 = 0x00000014U,  /**< SHAKE256, n=32, w=4  */
    VERUM_LEIGHTON_MICALI_OTS_SHAKE256_N32_W8 = 0x00000018U,  /**< SHAKE256, n=32, w=8  */
} VERUM_LEIGHTON_MICALI_OTS_typecode;

/**
 * @defgroup VERUM_LEIGHTON_MICALI_OTS_type_selection
 * @{
 *
 */

/**
 * @def        VERUM_LEIGHTON_MICALI_OTS_TYPE
 * @brief      Compile-time LM-OTS parameter set.
 * @details    Identifies the LM-OTS parameter set used throughout the library.
 *             This value is fixed at compile time and determines the hash
 *             function and the associated LM-OTS parameters (@c n, @c w, @c p,
 *             and @c ls) as specified by RFC 8554 and RFC 9858. The macro shall
 *             be defined to exactly one of the supported LM-OTS typecodes
 *             from ::VERUM_LEIGHTON_MICALI_OTS_typecode.
 *
 * @note       This implementation is statically configured for a single LM-OTS
 *             parameter set. All signatures, public keys, and private keys
 *             processed by the library shall use the parameter set identified
 *             by ::VERUM_LEIGHTON_MICALI_OTS_TYPE.
 *
 * @see        https://www.rfc-editor.org/rfc/rfc8554
 * @see        https://www.rfc-editor.org/rfc/rfc9858
 */
#define VERUM_LEIGHTON_MICALI_OTS_TYPE VERUM_LEIGHTON_MICALI_OTS_SHA256_N32_W8

/** @} */

#endif // VERUM_LEIGHTON_MICALI_OTS_SET_H_
