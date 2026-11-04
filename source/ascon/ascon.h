/**
 * @file      ascon.h
 * @brief     Ascon shared permutation primitives.
 * @details   Declares shared round constants, bit-interleaving conversions, and internal
 *            320-bit Ascon-p permutation layers for the Ascon cryptographic suite
 *            (NIST SP 800-232 Section 3).
 *
 *            State representation [OPT-A_0]: every 64-bit word S_w (w = 0..4) is held in
 *            bit-interleaved form π(S_w) = (E_w, O_w), with E_w = state[2w] holding the
 *            even-indexed bits s_{w,2k} and O_w = state[2w+1] holding the odd-indexed bits
 *            s_{w,2k+1} (k = 0..31). π is a bijection preserving ⊕, ∧ and ¬, so p_S runs
 *            unchanged on the E and O lanes; only p_L rotations and rate I/O are affected.
 *
 * @see       https://doi.org/10.6028/NIST.SP.800-232
 * @see       H. S. Warren Jr., Hacker's Delight, 2nd ed., Section 7-2 (2012).
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
 * @details      Bit-interleaved pairs π(C[𝑖]) = { E, O } XORed into S2 (state[4U], state[5U]).
 * @optimization [OPT-A_2] Pre-interleaved at compile time (no runtime π on constants); each
 *               8-bit C[𝑖] yields two 4-bit lanes, stored as uint8_t pairs: 24 B .rodata
 *               (vs. 48 B as uint32_t, 96 B as uint64_t), loaded with zero-extending byte loads.
 */
extern const uint8_t VERUM_ASCON_round_constants[12U][2U];

/**
 * @internal
 * @brief         π: (𝐿, 𝐻) → (𝐸, 𝑂). Converts one little-endian 64-bit word, given as its
 *                low/high 32-bit halves, to bit-interleaved form in place.
 * @param[in,out] word Entry: { 𝐿 = S mod 2^32, 𝐻 = ⌊S / 2^32⌋ }. Return: { 𝐸, 𝑂 }.
 * @optimization  [OPT-A_14] Loop-free delta-swap network: 4 stages per half (masks
 *                0x22222222, 0x0C0C0C0C, 0x00F000F0, 0x0000FF00) gather even bits into
 *                bits [0:15] and odd bits into [16:31], then one 16-bit merge forms 𝐸 and 𝑂.
 *                Constant-time, branch-free, 54 ALU ops per 64-bit word; cost
 *                confined to rate I/O, never inside the 8/12 permutation rounds.
 */
void VERUM_ASCON_interleave(uint32_t word[2U]);

/**
 * @internal
 * @brief         π⁻¹: (𝐸, 𝑂) → (𝐿, 𝐻). Converts one bit-interleaved word back to its
 *                little-endian low/high 32-bit halves in place.
 * @param[in,out] word Entry: { 𝐸, 𝑂 }. Return: { 𝐿, 𝐻 }.
 * @optimization  [OPT-A_14] Inverse network: 16-bit split, then the self-inverse delta
 *                swaps of π applied in reverse order (0x0000FF00 → 0x22222222).
 */
void VERUM_ASCON_deinterleave(uint32_t word[2U]);

#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
/**
 * @internal
 * @ref           NIST SP 800-232 Section 3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         Permutes the 320-bit ASCON state from @p round_index through round 11.
 * @param[in,out] state       320-bit bit-interleaved state as ten 32-bit words.
 * @param[out]    holder      320-bit scratch buffer for intermediate post-S-box values.
 * @param[in]     round_index Starting round index (0 for Ascon-p[12], 4 for Ascon-p[8]).
 * @optimization  [OPT-A_6] Noinline and shared across p[12] and p[8]; peels the initial
 *                p_C+p_S and final p_L outside the loop so the body executes only fused
 *                p_L+p_C+p_S rounds, minimizing .text footprint and I-cache pressure.
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
 * @param[in,out] state          320-bit bit-interleaved state as ten 32-bit words.
 * @param[out]    holder         320-bit scratch buffer receiving post-S-box words.
 * @param[in]     round_constant Bit-interleaved round constant π(C[i]) = { E, O }.
 * @optimization  [OPT-A_3] p_C folded into the S2 ^= S1 pre-mix.
 *                [OPT-A_4] Bit-sliced S-box on E and O lanes with NOT-AND (~x & y) and ~x,
 *                written directly into holder[0U..9U] without extra temporaries.
 */
inline void VERUM_ASCON_permute_substitution_layer(uint32_t state[10U],
                                                                  uint32_t holder[10U],
                                                                  const uint8_t round_constant[2U]);

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3.4
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        𝑝𝐿 Linear Diffusion Layer
 * @param[out]   state  320-bit bit-interleaved state receiving diffused words.
 * @param[in]    holder 320-bit scratch buffer holding post-substitution words.
 * @optimization [OPT-A_1] Each 64-bit rotation becomes two native 32-bit rotations
 *               (see ascon.c for the rotation map).
 */
inline void VERUM_ASCON_permute_linear_diffusion_layer(uint32_t state[10U],
                                                                       uint32_t holder[10U]);

/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2, 3.3, and 3.4
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐿 Linear Diffusion Layer; 𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @param[out]    state          320-bit bit-interleaved state buffer.
 * @param[in,out] holder         320-bit scratch buffer updated across merged rounds.
 * @param[in]     round_constant Bit-interleaved round constant π(C[i]) = { E, O }.
 * @optimization  [OPT-A_5] Fuses p_L of round i-1 with p_C and p_S of round i, diffusing
 *                S4 and S2 ahead of S0 and S3 so the S-box pre-mix (S0 ^= S4,
 *                S2 ^= S1 ^ C[i], S4 ^= S3) folds into the diffusion stores.
 *                [OPT-A_1] Interleaved p_L; [OPT-A_4] NOT-AND S-box.
 */

 inline void VERUM_ASCON_permute_merged(uint32_t state[10U],
                                            uint32_t holder[10U],
                                                    const uint8_t round_constant[2U]);

#endif // VERUM_OPTIMIZATION_MEMORY_DEF

#endif // VERUM_ASCON_H_
