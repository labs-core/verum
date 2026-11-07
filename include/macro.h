/**
 * @file      macro.h
 * @brief     Compiler attribute and abstraction macros.
 * @details   Defines attribute macros for function inlining, noinline,
 *            noreturn, and volatile semantics across toolchains.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_MACRO_H_
#define VERUM_MACRO_H_

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
 * @brief      Volatile qualifier to prevent compiler dead-store elimination.
 *
 * @details    Mandated by FIPS 140-3 (ISO/IEC 19790:2012 Section 7.9.7) to ensure
 *             zeroization of sensitive security parameters (SSPs) is not elided
 *             by optimizing compilers.
 */
#define VERUM_ATTR_VOLATILE volatile

/**
 * @brief      Indicates to the compiler that the decorated function does not return.
 *
 * @details    Applied to safety-critical fault handlers and fatal error traps.
 */
#define VERUM_ATTR_NORETURN _Noreturn

#endif /* VERUM_MACRO_H_ */
