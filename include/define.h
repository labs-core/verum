/**
 * @file      define.h
 * @brief     Project-wide feature-selection and configuration definitions.
 * @details   Defines optional feature flags consumed throughout the VERUM
 *            codebase. This header must be included before any other VERUM
 *            header. All feature flags default to their disabled state and
 *            must be explicitly defined here to activate the corresponding behaviour.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_DEFINE_H_
#define VERUM_DEFINE_H_

#include "macro.h"

/**
 * @defgroup VERUM_FEATURE_FLAGS Optional feature flags
 * @{
 */

/**
 * @def        VERUM_OPTIMIZATION_MEMORY_DEF
 * @brief      Enable memory-footprint optimisations.
 * @details    When defined, the implementation trades computational throughput
 *             for reduced static and stack memory usage and data footprint outweigh cycle count.
 */
#ifdef VERUM_CUSTOM_CONFIG
    #ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        #undef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    #endif /* VERUM_OPTIMIZATION_MEMORY_DEF */
#else /* VERUM_CUSTOM_CONFIG */
    #define VERUM_OPTIMIZATION_MEMORY_DEF

    #ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        #undef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    #endif /* VERUM_OPTIMIZATION_MEMORY_DEF */
#endif /* VERUM_CUSTOM_CONFIG */

/**
 * @def        VERUM_FAULT_HANDLER
 * @brief      Platform fault handler invoked on a detected computation error or self-test failure.
 * @details    Must be defined to a no-return function or macro that is called
 *             when @c VERUM_SECURITY_REDUNDANCY_DEF detects a mismatch between
 *             the two computation results, or when @c VERUM_STANDARD_FIPS_140_3_DEF
 *             detects a KAT or self-test failure. The handler must not return.
 *             Required when @c VERUM_SECURITY_REDUNDANCY_DEF or
 *             @c VERUM_STANDARD_FIPS_140_3_DEF is defined.
 *
 *             Example:
 *             @code
 *             #define VERUM_FAULT_HANDLER() platform_safe_state()
 *             @endcode
 */
#undef VERUM_FAULT_HANDLER

/**
 * @def        VERUM_STANDARD_FIPS_140_3_DEF
 * @brief      Enable FIPS 140-3 compliance mode.
 * @details    When defined, activates the full set of controls mandated by
 *             FIPS 140-3 (ISO/IEC 19790:2012) for a software cryptographic
 *             module. The following requirements are enforced:
 *
 *             - Power-on self-tests (Section 9.5). On every cold
 *               initialisation the module executes the Known-Answer Tests for
 *               each enabled primitive (AEAD128, Hash256, XOF128, CXOF128). A failure
 *               places the module in a permanent error state from which no
 *               cryptographic output is produced and @c VERUM_FAULT_HANDLER is
 *               invoked.
 *             - Conditional self-tests (Section 9.6). A pair-wise consistency
 *               check is performed on each key prior to its first use in an
 *               encrypt or decrypt operation. If the check fails the key is
 *               rejected and @c VERUM_FAULT_HANDLER is invoked.
 *             - Zeroization of sensitive data (Section 9.7). All cryptographic
 *               variables — key copies, the Ascon permutation state,
 *               authentication tag intermediates, and XOF and CXOF squeeze buffers —
 *               are overwritten with zeroes before the enclosing function
 *               returns. Stores are issued through @c VERUM_ATTR_VOLATILE
 *               pointers to prevent the optimiser from eliding them as dead
 *               stores.
 *
 *             Enabling this flag increases code size, startup latency, and
 *             per-call overhead. @c VERUM_FAULT_HANDLER is invoked on any fault.
 */
#ifdef VERUM_CUSTOM_CONFIG
#else /* VERUM_CUSTOM_CONFIG */
    #define VERUM_STANDARD_FIPS_140_3_DEF
#endif /* VERUM_CUSTOM_CONFIG */


/** @} */

#endif /* VERUM_DEFINE_H_ */
