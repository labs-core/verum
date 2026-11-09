/**
 * @file      types.h
 * @brief     Common type definitions.
 * @details   This header defines fundamental data types, structures, and aliases
 *            to promote consistency and portability. It also enables
 *            aliasing between types on another projects that may want to use VERUM.
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#ifndef VERUM_STD_TYPES_H_
#define VERUM_STD_TYPES_H_


#ifdef NULL
#else /* NULL */
    #define NULL ((void *) 0)
#endif /* NULL */

typedef unsigned char uint8_t;
// cppcheck-suppress misra-c2012-2.3 ; DEV-010: Standard type definitions for library-wide usage.
typedef signed char int8_t;
typedef unsigned int uint32_t;
// cppcheck-suppress misra-c2012-2.3 ; DEV-010: Standard type definitions for library-wide usage.
typedef signed int int32_t;

#endif // VERUM_STD_TYPES_H_
