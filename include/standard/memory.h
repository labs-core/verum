/**
 * @file      memory.h
 * @brief     Common memory operation definitions.
 * @details   This header defines fundamental memory operations as inline
 *            functions to promote consistency and portability without
 *            depending on the C standard library. It also enables
 *            aliasing between types on another projects that may want to
 *            use VERUM.
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
*/
#ifndef VERUM_STD_MEMORY_H_
#define VERUM_STD_MEMORY_H_

#include "standard/types.h"

void *verum_memcpy(void *destination, const void *source, uint32_t size)
{
    uint8_t       *d = dest;
    const uint8_t *s = src;

    do
    {
        *d++ = *s++;
    }while(n>0);

    return dest;
}

#endif /* VERUM_STD_MEMORY_H_ */