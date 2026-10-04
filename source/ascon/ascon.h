/**
 * @file      ascon.h
 * @brief     Ascon shared primitives.
 * @details   This header defines shared constants, types, and internal helper functions 
 *            for the Ascon family of authenticated encryption algorithms.
 *
 * @see       https://doi.org/10.6028/NIST.SP.800-232
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */

#ifndef VERUM_ASCON_H_
#define VERUM_ASCON_H_

#include "standard/types.h"
#include "define.h"

#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
#include "auxiliary/memory.h"
#endif // VERUM_OPTIMIZATION_MEMORY_DEF


/**
 * @internal
 * @ref NIST SP 800-232 Section 3.2 Table 5
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief C[𝑖] = Const[16−𝑟𝑛𝑑+𝑖]
 * @details Each of these are little endian; The XOR will be bounded to the most significant bit of the 5th word of the state.
 */
extern const uint32_t VERUM_ASCON_round_constants[12U];

#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
/**
 * @internal
 * @brief Permutes the ASCON state starting from a specified round.
 * @param[inout] state The ASCON state to be permuted.
 * @param[out] holder A buffer to hold intermediate state values.
 * @param[in] round_index The index of the current round.
 * @optimization This function allows for a more compact implementation of the permutation rounds by reducing code duplication and improving instruction cache utilization.
 */
void VERUM_ASCON_permute(uint32_t state[10U],
                                        uint32_t * holder,
                                        uint32_t round_index);
#else
/**
 * @internal
 * @ref NIST SP 800-232 Section 3.3
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief 𝑝𝑆 Substitution Layer
 * @optimization Uses 4 temporaries instead of 10, reducing memory traffic (fewer loads/stores), lowering stack usage, and easing register pressure for better overall efficiency.
 */
inline void VERUM_ASCON_permute_substitution_layer(uint32_t state[10U],
                                                                  uint32_t holder[10U],
                                                                   uint32_t round_constant);

/**
 * @internal
 * @ref NIST SP 800-232 Section 3.4
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief 𝑝𝐿 Linear Diffusion Layer
 */
inline void VERUM_ASCON_permute_linear_diffusion_layer(uint32_t state[10U],
                                                                       uint32_t holder[10U]);

/**
 * @internal
 * @ref NIST SP 800-232 Section 3.4
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief 𝑝𝐿 Linear Diffusion Layer; 𝑝𝑆 Substitution Layer; 𝑝𝐶 Constant-Addition Layer
 * @optimization The linear diffusion layer is merged with the next round's initial permutation step, reducing the number of intermediate state stores and loads, which can improve performance by minimizing memory access overhead.
 */

 inline void VERUM_ASCON_permute_merged(uint32_t state[10U],
                                            uint32_t holder[10U],
                                                    uint32_t round_constant);

#endif // VERUM_OPTIMIZATION_MEMORY_DEF

#endif // VERUM_ASCON_H_
