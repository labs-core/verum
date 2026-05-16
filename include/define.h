/**
 * @file      define.h
 * @brief     Project-wide compiler and feature macros.
 * @details   This header defines compiler abstraction macros and
 *            optional feature flags used throughout the VERUM codebase.
 *            It must be included before any other VERUM header.
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
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
 *             a function call boundary is not acceptable.
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
 * @brief      Enable memory optimizations.
 */
#define VERUM_OPTIMIZATION_MEMORY_DEF

/**
 * @def        VERUM_STANDARD_FIPS_140_3_DEF
 * @brief      Enable FIPS 140-3 compliance.
 */
#define VERUM_STANDARD_FIPS_140_3_DEF

#endif /* VERUM_DEFINE_H_ */
