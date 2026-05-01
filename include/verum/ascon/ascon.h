#ifndef VERUM_ASCON_H_
#define VERUM_ASCON_H_

#include "standard/types.h"

typedef union
{
    typedef struct 
    {
        uint32_t initialization_vector[2];
        uint32_t key[4];
        uint32_t nonce[4];
    } 
    ASCON_STATE0;
    uint32_t buffer[10];
}ASCON_state_t;


#endif