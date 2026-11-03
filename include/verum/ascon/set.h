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

/**
 * @defgroup VERUM_ASCON_AEAD128_feature_flags Ascon-AEAD128 Feature Flags
 * @{
 */

/**
 * @def          VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
 * @brief        Enable associated-data authentication in Ascon-AEAD128.
 * @details      When defined, @c VERUM_ASCON_AEAD128_encrypt and @c VERUM_ASCON_AEAD128_decrypt
 *               accept @p associated_data and @p associated_size and authenticate that data
 *               (unencrypted) during tag generation. When undefined, both parameters and the
 *               associated-data absorption phase are omitted.
 * @optimization Undefining this macro strips the 16-byte AD staging buffer and the Ascon-p[8]
 *               AD absorption phase at compile time, reducing stack and .text footprint on
 *               targets that do not require AD support.
 * @warning      When defined, the AD absorption and padding phase executes unconditionally;
 *               undefine this macro when operating without associated data.
 */
#define VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

/** @} */


#endif /* VERUM_ASCON_SET_H_ */
