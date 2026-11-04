/**
 * @file      ascon.h
 * @brief     Ascon shared permutation primitives.
 * @details   Declares shared round constants and internal 320-bit Ascon-p permutation
 *            layers for the Ascon cryptographic suite (NIST SP 800-232 Section 3).
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

#ifndef VERUM_ASCON_H_
#define VERUM_ASCON_H_

#include "standard/types.h"
#include "define.h"

#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
#include "auxiliary/memory.h"
#endif // VERUM_OPTIMIZATION_MEMORY_DEF


/**
 * @internal
 * @ref          NIST SP 800-232 Section 3.2 Table 5
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        C[𝑖] = Const[16−𝑟𝑛𝑑+𝑖]
 * @details      Little-endian 32-bit round constants XORed into the lower word of S2 (state[4U]).
 * @optimization Stored as 32-bit words rather than 64-bit words because bits [8:63] of every
 *               round constant are zero, halving .rodata footprint (48 B vs. 96 B) and eliding
 *               upper-word XORs on state[5U].
 */
extern const uint32_t VERUM_ASCON_round_constants[12U];

#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
/**
 * @internal
 * @ref           NIST SP 800-232 Section 3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         Permutes the 320-bit ASCON state from @p round_index through round 11.
 * @param[in,out] state       320-bit state as ten 32-bit words.
 * @param[out]    holder      320-bit scratch buffer for intermediate post-S-box values.
 * @param[in]     round_index Starting round index (0 for Ascon-p[12], 4 for Ascon-p[8]).
 * @optimization  Marked noinline and shared across p[12] and p[8]; peels the initial
 *                substitution layer and final linear diffusion layer outside the loop so
 *                the body executes only fused p_L+p_C+p_S rounds, minimizing .text
 *                footprint and instruction-cache pressure.
 */
void VERUM_ASCON_permute(uint32_t state[10U],
                                        uint32_t * holder,
                                        uint32_t round_index);
#else
/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2 and 3.3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @param[in,out] state          320-bit state as ten 32-bit words.
 * @param[out]    holder         320-bit scratch buffer receiving post-S-box words.
 * @param[in]     round_constant Round constant C[i] for the initial round.
 * @optimization  Fuses p_C (state[4U] ^= round_constant) into the first S-box XOR and
 *                evaluates the 5-bit S-box in 32-bit bit-sliced form directly into
 *                holder[0U..9U] using bitwise NOT-AND (~x & y) and ~x without additional
 *                temporaries, reducing stack usage, register pressure, and memory traffic.
 */
inline void VERUM_ASCON_permute_substitution_layer(uint32_t state[10U],
                                                                  uint32_t holder[10U],
                                                                   uint32_t round_constant);

/**
 * @internal
 * @ref        NIST SP 800-232 Section 3.4
 * @see        https://doi.org/10.6028/NIST.SP.800-232
 * @brief      𝑝𝐿 Linear Diffusion Layer
 * @param[out] state  320-bit state receiving diffused words.
 * @param[in]  holder 320-bit scratch buffer holding post-substitution words.
 */
inline void VERUM_ASCON_permute_linear_diffusion_layer(uint32_t state[10U],
                                                                       uint32_t holder[10U]);

/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2, 3.3, and 3.4
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐿 Linear Diffusion Layer; 𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @param[out]    state          320-bit state buffer.
 * @param[in,out] holder         320-bit scratch buffer updated across merged rounds.
 * @param[in]     round_constant Round constant C[i] for the next round.
 * @optimization  Fuses p_L of round i-1 with p_C and p_S of round i, scheduling diffusion
 *                of S4 (state[8U..9U]) and S2 (state[4U..5U]) ahead of S0 and S3 so the
 *                initial S-box XORs (S0 ^= S4, S2 ^= S1 ^ C[i], S4 ^= S3) fold directly
 *                into diffusion stores, eliminating inter-round state loads and stores.
 */

 inline void VERUM_ASCON_permute_merged(uint32_t state[10U],
                                            uint32_t holder[10U],
                                                    uint32_t round_constant);

#endif // VERUM_OPTIMIZATION_MEMORY_DEF

#endif // VERUM_ASCON_H_
