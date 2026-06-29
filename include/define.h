/**
 * @file      define.h
 * @brief     Project-wide compiler abstraction and feature-selection macros.
 * @details   Defines compiler attribute wrappers and optional feature flags
 *            consumed throughout the VERUM codebase. This header must be
 *            included before any other VERUM header. All feature flags default
 *            to their disabled state and must be explicitly defined 
 *            here to activate the corresponding behaviour.
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

/**
 * @brief      Force the compiler to always inline the decorated function.
 *
 * @details    Unlike @c static @c inline, which is a hint the compiler may
 *             ignore, @c VERUM_ATTR_INLINE mandates inlining and causes a
 *             compile-time error if the function cannot be inlined (e.g.
 *             its address is taken or recursion is detected). Use for
 *             performance-critical and side-channel-sensitive paths where
 *             a function-call boundary is not acceptable.
 */
#define VERUM_ATTR_INLINE __attribute__((always_inline))

/**
 * @brief      Prevent the compiler from inlining the decorated function.
 *
 * @details    Applied to functions whose call sites must remain distinct
 *             in the binary, either to bound code-size growth from
 *             repeated inlining or to preserve a stable symbol for
 *             profiling and debugging.
 */
#define VERUM_ATTR_NOINLINE __attribute__((noinline))

/**
 * @defgroup verum_feature_flags Optional feature flags
 * @{
 */

/**
 * @def        VERUM_OPTIMIZATION_MEMORY_DEF
 * @brief      Enable memory-footprint optimisations.
 * @details    When defined, the implementation trades computational throughput
 *             for reduced static and stack memory usage and data footprint outweigh cycle count.
 */
#undef VERUM_OPTIMIZATION_MEMORY_DEF

/**
 * @def        VERUM_FAULT_HANDLER
 * @brief      Platform fault handler invoked on a detected computation error.
 * @details    Must be defined to a no-return function or macro that is called
 *             when @c VERUM_SECURITY_REDUNDANCY_DEF detects a mismatch between
 *             the two computation results, or when @c VERUM_STANDARD_FIPS_140_3_DEF
 *             detects a KAT failure. The handler must not return. Required when
 *             @c VERUM_SECURITY_REDUNDANCY_DEF or
 *             @c VERUM_STANDARD_FIPS_140_3_DEF is defined.
 *
 *             Example:
 *             @code
 *             #define VERUM_FAULT_HANDLER() platform_safe_state()
 *             @endcode
 */
#undef VERUM_FAULT_HANDLER


//#ifdef VERUM_FAULT_HANDLER
/**
 * @def        VERUM_STANDARD_FIPS_140_3_DEF
 * @brief      Enable FIPS 140-3 compliance mode.
 * @details    When defined, activates the full set of controls mandated by
 *             FIPS 140-3 (ISO/IEC 19790:2012) for a software cryptographic
 *             module. The following requirements are enforced:
 *
 *              [TODO]
 *             - Power-on self-tests (Section 9.5). On every cold
 *               initialisation the module executes the Known-Answer Tests for
 *               each enabled primitive (AEAD128, Hash256, XOF128). A failure
 *               places the module in a permanent error state from which no
 *               cryptographic output is produced and @c VERUM_FAULT_HANDLER is
 *               invoked.
 *              [TODO]
 *             - Conditional self-tests (Section 9.6). A pair-wise consistency
 *               check is performed on each key prior to its first use in an
 *               encrypt or decrypt operation. If the check fails the key is
 *               rejected and @c VERUM_FAULT_HANDLER is invoked.
 *              [DONE]
 *             - Zeroization of sensitive data (Section 9.7). All cryptographic
 *               variables — key copies, the Ascon permutation state,
 *               authentication tag intermediates, and XOF squeeze buffers —
 *               are overwritten with zeroes before the enclosing function
 *               returns. Stores are issued through @c VERUM_ATTR_VOLATILE
 *               pointers to prevent the optimiser from eliding them as dead
 *               stores.
 *
 *             Enabling this flag increases code size, startup latency, and
 *             per-call overhead. @c VERUM_FAULT_HANDLER must be defined when
 *             this flag is active.
 */
#define VERUM_STANDARD_FIPS_140_3_DEF
//#endif /* VERUM_FAULT_HANDLER */


/** @} */

#endif /* VERUM_DEFINE_H_ */
