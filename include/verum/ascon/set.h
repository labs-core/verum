
/**
 * @file      set.h
 * @brief     Ascon feature-selection configuration macros.
 * @details   Declares optional feature-selection macros for the Ascon public interfaces.
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
 * @defgroup VERUM_ASCON_AEAD128_feature_flags
 * @{
 *
 */

/**
 * @def        VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
 * @brief      Enable associated-data processing in Ascon-AEAD128.
 * @details    When defined, the @c VERUM_ASCON_AEAD128_encrypt and
 *             @c VERUM_ASCON_AEAD128_decrypt functions accept two additional
 *             parameters — @p associated_data and @p associated_size — and
 *             authenticate that data as part of tag generation. The associated
 *             data is not encrypted.
 *
 *             When left undefined, the associated-data parameters are omitted
 *             from the function signatures and the associated-data absorption
 *             phase is skipped entirely, reducing code size on targets that do
 *             not require AD support.
 */
#define VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

/** @} */


#endif /* VERUM_ASCON_SET_H_ */