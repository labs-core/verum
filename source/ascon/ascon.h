/**
 * @file      ascon.h
 * @brief     Ascon shared permutation primitives.
 * @details   Declares shared round constants, bit-interleaving conversions, and internal
 *            320-bit Ascon-p permutation layers for the Ascon cryptographic suite
 *            (NIST SP 800-232 Section 3).
 *
 *            State representation [OPT-A_0]: when VERUM_ASCON_BIT_INTERLEAVING_DEF is
 *            defined, every 64-bit word S_w (w = 0..4) is held in bit-interleaved form
 *            π(S_w) = (E_w, O_w), with E_w = state_2w holding even-indexed bits and
 *            O_w = state_{2w+1} holding odd-indexed bits (k = 0..31). π is a bijection
 *            preserving ⊕, ∧ and ¬, so p_S runs unchanged on the E and O lanes; only
 *            p_L rotations and rate I/O are affected. When undefined, direct low/high
 *            halves (L_w, H_w) are used.
 *
 *            Scalar register allocation [OPT-A_13]: the 320-bit state S and 320-bit
 *            post-substitution scratch buffer H are decomposed into twenty independent
 *            32-bit register-qualified scalars (state_0..state_9, holder_0..holder_9)
 *            within each cryptographic processing engine. Because ISO C11 is strictly
 *            pass-by-value and forbids applying the unary address-of operator (&) to
 *            register-qualified objects (ISO/IEC 9899:2011 Section 6.5.3.2), the unrolled
 *            round layers and full permutation schedules (Ascon-p[12], Ascon-p[8]) are
 *            exposed as statement macros that mutate the twenty register variables in
 *            place without pointer indirection or stack-frame spilling, while preserving
 *            the corresponding C function definitions in ascon.c.
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
#include "macro.h"
#include "verum/ascon/set.h"

#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
#include "auxiliary/memory.h"
#endif /* VERUM_OPTIMIZATION_MEMORY_DEF */

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3.2 Table 5
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        C[𝑖] = Const[16−𝑟𝑛𝑑+𝑖]
 * @details      Round constants XORed into S2.
 * @optimization [OPT-A_2] Pre-computed at compile time (no runtime conversion on constants).
 *               Under bit interleaving: stored as pairs of uint8_t (24 B .rodata vs. 48 B / 96 B),
 *               loaded with zero-extending byte loads into state_4 (state[4U]) and state_5 (state[5U]).
 *               Under direct halves: stored as uint32_t words (48 B .rodata vs. 96 B) and
 *               XORed exclusively into the lower word state_4 (state[4U]).
 */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
extern const uint8_t VERUM_ASCON_round_constants[12U][2U];
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
extern const uint32_t VERUM_ASCON_round_constants[12U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
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
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2 and 3.3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @details       Executes the initial constant addition and 5-bit affine/chi S-box layer
 *                of an Ascon-p permutation schedule. Provided both as a documented
 *                C function on array-backed state and as a register-pinned statement macro
 *                operating directly on twenty 32-bit scalar register variables.
 * @param[in,out] state          320-bit state as ten 32-bit words (state_0..state_9).
 * @param[out]    holder         320-bit scratch buffer receiving post-S-box words (holder_0..holder_9).
 * @param[in]     round_constant Round constant (interleaved uint8_t[2U] pair or 32-bit word).
 * @optimization  [OPT-A_3] p_C folded into the S2 ^= S1 pre-mix, saving a separate
 *                read-modify-write on state_4 and state_5.
 *                [OPT-A_4] Bit-sliced S-box on 32-bit words with NOT-AND (~x & y) and ~x,
 *                written directly into holder_0..holder_9 without extra temporaries.
 *                [OPT-A_13] In-place scalar register mutation via VERUM_ASCON_PERMUTE_SUBSTITUTION_LAYER,
 *                avoiding array indexing and pointer-to-register constraints.
 */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
void VERUM_ASCON_permute_substitution_layer(uint32_t state[10U],
                                            uint32_t holder[10U],
                                            const uint8_t round_constant[2U]);

#define VERUM_ASCON_PERMUTE_SUBSTITUTION_LAYER(state_0, state_1, state_2, state_3, state_4, \
                                               state_5, state_6, state_7, state_8, state_9, \
                                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                                               round_constant) do { \
    (state_0) = (state_0) ^ (state_8); \
    (state_1) = (state_1) ^ (state_9); \
\
    (state_4) = (state_4) ^ (state_2) ^ (uint32_t) (round_constant)[0U]; \
    (state_5) = (state_5) ^ (state_3) ^ (uint32_t) (round_constant)[1U]; \
\
    (state_8) = (state_8) ^ (state_6); \
    (state_9) = (state_9) ^ (state_7); \
\
    (holder_0) = (state_0) ^ ((~(state_2)) & (state_4)); \
    (holder_1) = (state_1) ^ ((~(state_3)) & (state_5)); \
    (holder_2) = (state_2) ^ ((~(state_4)) & (state_6)) ^ (holder_0); \
    (holder_3) = (state_3) ^ ((~(state_5)) & (state_7)) ^ (holder_1); \
    (holder_4) = (state_4) ^ ((~(state_6)) & (state_8)); \
    (holder_5) = (state_5) ^ ((~(state_7)) & (state_9)); \
    (holder_6) = (state_6) ^ ((~(state_8)) & (state_0)) ^ (holder_4); \
    (holder_7) = (state_7) ^ ((~(state_9)) & (state_1)) ^ (holder_5); \
    (holder_8) = (state_8) ^ ((~(state_0)) & (state_2)); \
    (holder_9) = (state_9) ^ ((~(state_1)) & (state_3)); \
\
    (holder_0) = (holder_0) ^ (holder_8); \
    (holder_1) = (holder_1) ^ (holder_9); \
    (holder_4) = ~(holder_4); \
    (holder_5) = ~(holder_5); \
} while (0)
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
void VERUM_ASCON_permute_substitution_layer(uint32_t state[10U],
                                            uint32_t holder[10U],
                                            uint32_t round_constant);

#define VERUM_ASCON_PERMUTE_SUBSTITUTION_LAYER(state_0, state_1, state_2, state_3, state_4, \
                                               state_5, state_6, state_7, state_8, state_9, \
                                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                                               round_constant) do { \
    (state_0) = (state_0) ^ (state_8); \
    (state_1) = (state_1) ^ (state_9); \
\
    (state_4) = (state_4) ^ (state_2) ^ (round_constant); \
    (state_5) = (state_5) ^ (state_3); \
\
    (state_8) = (state_8) ^ (state_6); \
    (state_9) = (state_9) ^ (state_7); \
\
    (holder_0) = (state_0) ^ ((~(state_2)) & (state_4)); \
    (holder_1) = (state_1) ^ ((~(state_3)) & (state_5)); \
    (holder_2) = (state_2) ^ ((~(state_4)) & (state_6)) ^ (holder_0); \
    (holder_3) = (state_3) ^ ((~(state_5)) & (state_7)) ^ (holder_1); \
    (holder_4) = (state_4) ^ ((~(state_6)) & (state_8)); \
    (holder_5) = (state_5) ^ ((~(state_7)) & (state_9)); \
    (holder_6) = (state_6) ^ ((~(state_8)) & (state_0)) ^ (holder_4); \
    (holder_7) = (state_7) ^ ((~(state_9)) & (state_1)) ^ (holder_5); \
    (holder_8) = (state_8) ^ ((~(state_0)) & (state_2)); \
    (holder_9) = (state_9) ^ ((~(state_1)) & (state_3)); \
\
    (holder_0) = (holder_0) ^ (holder_8); \
    (holder_1) = (holder_1) ^ (holder_9); \
    (holder_4) = ~(holder_4); \
    (holder_5) = ~(holder_5); \
} while (0)
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3.4
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        𝑝𝐿 Linear Diffusion Layer: Σ𝑤(S𝑤) = S𝑤 ⊕ (S𝑤 ⋙ 𝑟1) ⊕ (S𝑤 ⋙ 𝑟2)
 * @details      Executes the terminal linear diffusion layer of an Ascon-p
 *               permutation schedule, diffusing post-S-box words from holder_0..holder_9
 *               back into state_0..state_9.
 * @param[out]   state  320-bit state receiving diffused words (state_0..state_9).
 * @param[in]    holder 320-bit scratch buffer holding post-substitution words (holder_0..holder_9).
 * @optimization [OPT-A_1] 32-bit native rotations (bit-interleaving) or 64-bit cross-word
 *               rotations (direct halves).
 *               [OPT-A_13] In-place scalar register mutation via VERUM_ASCON_PERMUTE_LINEAR_DIFFUSION_LAYER.
 */
void VERUM_ASCON_permute_linear_diffusion_layer(uint32_t state[10U],
                                                const uint32_t holder[10U]);

#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
#define VERUM_ASCON_PERMUTE_LINEAR_DIFFUSION_LAYER(state_0, state_1, state_2, state_3, state_4, \
                                                   state_5, state_6, state_7, state_8, state_9, \
                                                   holder_0, holder_1, holder_2, holder_3, holder_4, \
                                                   holder_5, holder_6, holder_7, holder_8, holder_9) do { \
    (state_0) = (holder_0) ^ (((holder_1) >>  9U) | ((holder_1) << 23U)) ^ (((holder_0) >> 14U) | ((holder_0) << 18U)); \
    (state_1) = (holder_1) ^ (((holder_0) >> 10U) | ((holder_0) << 22U)) ^ (((holder_1) >> 14U) | ((holder_1) << 18U)); \
\
    (state_2) = (holder_2) ^ (((holder_3) >> 30U) | ((holder_3) <<  2U)) ^ (((holder_3) >> 19U) | ((holder_3) << 13U)); \
    (state_3) = (holder_3) ^ (((holder_2) >> 31U) | ((holder_2) <<  1U)) ^ (((holder_2) >> 20U) | ((holder_2) << 12U)); \
\
    (state_4) = (holder_4) ^ (holder_5) ^ (((holder_4) >>  3U) | ((holder_4) << 29U)); \
    (state_5) = (holder_5) ^ (((holder_4) >>  1U) | ((holder_4) << 31U)) ^ (((holder_5) >>  3U) | ((holder_5) << 29U)); \
\
    (state_6) = (holder_6) ^ (((holder_6) >>  5U) | ((holder_6) << 27U)) ^ (((holder_7) >>  8U) | ((holder_7) << 24U)); \
    (state_7) = (holder_7) ^ (((holder_7) >>  5U) | ((holder_7) << 27U)) ^ (((holder_6) >>  9U) | ((holder_6) << 23U)); \
\
    (state_8) = (holder_8) ^ (((holder_9) >>  3U) | ((holder_9) << 29U)) ^ (((holder_9) >> 20U) | ((holder_9) << 12U)); \
    (state_9) = (holder_9) ^ (((holder_8) >>  4U) | ((holder_8) << 28U)) ^ (((holder_8) >> 21U) | ((holder_8) << 11U)); \
} while (0)
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
#define VERUM_ASCON_PERMUTE_LINEAR_DIFFUSION_LAYER(state_0, state_1, state_2, state_3, state_4, \
                                                   state_5, state_6, state_7, state_8, state_9, \
                                                   holder_0, holder_1, holder_2, holder_3, holder_4, \
                                                   holder_5, holder_6, holder_7, holder_8, holder_9) do { \
    (state_0) = (holder_0) ^ (((holder_0) >> 19U) | ((holder_1) << 13U)) ^ (((holder_0) >> 28U) | ((holder_1) << 4U)); \
    (state_1) = (holder_1) ^ (((holder_1) >> 19U) | ((holder_0) << 13U)) ^ (((holder_1) >> 28U) | ((holder_0) << 4U)); \
\
    (state_2) = (holder_2) ^ (((holder_2) << 3U) | ((holder_3) >> 29U)) ^ (((holder_2) << 25U) | ((holder_3) >> 7U)); \
    (state_3) = (holder_3) ^ (((holder_3) << 3U) | ((holder_2) >> 29U)) ^ (((holder_3) << 25U) | ((holder_2) >> 7U)); \
\
    (state_4) = (holder_4) ^ (((holder_4) >>  1U) | ((holder_5) << 31U)) ^ (((holder_4) >>  6U) | ((holder_5) << 26U)); \
    (state_5) = (holder_5) ^ (((holder_5) >>  1U) | ((holder_4) << 31U)) ^ (((holder_5) >>  6U) | ((holder_4) << 26U)); \
\
    (state_6) = (holder_6) ^ (((holder_6) >> 10U) | ((holder_7) << 22U)) ^ (((holder_6) >> 17U) | ((holder_7) << 15U)); \
    (state_7) = (holder_7) ^ (((holder_7) >> 10U) | ((holder_6) << 22U)) ^ (((holder_7) >> 17U) | ((holder_6) << 15U)); \
\
    (state_8) = (holder_8) ^ (((holder_8) >>  7U) | ((holder_9) << 25U)) ^ (((holder_8) << 23U) | ((holder_9) >> 9U)); \
    (state_9) = (holder_9) ^ (((holder_9) >>  7U) | ((holder_8) << 25U)) ^ (((holder_9) << 23U) | ((holder_8) >> 9U)); \
} while (0)
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2, 3.3, and 3.4
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐿 Linear Diffusion Layer; 𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @details       Executes one fused interior round transition (p_L of round i-1 merged
 *                with p_C and p_S of round i).
 * @param[out]    state          320-bit state buffer (state_0..state_9).
 * @param[in,out] holder         320-bit scratch buffer updated across merged rounds (holder_0..holder_9).
 * @param[in]     round_constant Round constant (interleaved uint8_t[2U] pair or 32-bit word).
 * @optimization  [OPT-A_5] Fuses p_L of round i-1 with p_C and p_S of round i, diffusing
 *                S4 and S2 ahead of S0 and S3 so the S-box pre-mix (S0 ^= S4,
 *                S2 ^= S1 ^ C[i], S4 ^= S3) folds into the diffusion stores.
 *                [OPT-A_1] Interleaved or direct-halves p_L; [OPT-A_3] p_C fold; [OPT-A_4] NOT-AND S-box.
 *                [OPT-A_13] In-place scalar register mutation via VERUM_ASCON_PERMUTE_MERGED.
 */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
void VERUM_ASCON_permute_merged(uint32_t state[10U],
                                uint32_t holder[10U],
                                const uint8_t round_constant[2U]);

#define VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                                   state_5, state_6, state_7, state_8, state_9, \
                                   holder_0, holder_1, holder_2, holder_3, holder_4, \
                                   holder_5, holder_6, holder_7, holder_8, holder_9, \
                                   round_constant) do { \
    (state_8) = (holder_8) ^ (((holder_9) >>  3U) | ((holder_9) << 29U)) ^ (((holder_9) >> 20U) | ((holder_9) << 12U)); \
    (state_9) = (holder_9) ^ (((holder_8) >>  4U) | ((holder_8) << 28U)) ^ (((holder_8) >> 21U) | ((holder_8) << 11U)); \
\
    (state_0) = ((holder_0) ^ (((holder_1) >>  9U) | ((holder_1) << 23U)) ^ (((holder_0) >> 14U) | ((holder_0) << 18U))) ^ (state_8); \
    (state_1) = ((holder_1) ^ (((holder_0) >> 10U) | ((holder_0) << 22U)) ^ (((holder_1) >> 14U) | ((holder_1) << 18U))) ^ (state_9); \
\
    (state_2) = (holder_2) ^ (((holder_3) >> 30U) | ((holder_3) <<  2U)) ^ (((holder_3) >> 19U) | ((holder_3) << 13U)); \
    (state_3) = (holder_3) ^ (((holder_2) >> 31U) | ((holder_2) <<  1U)) ^ (((holder_2) >> 20U) | ((holder_2) << 12U)); \
\
    (state_4) = ((holder_4) ^ (holder_5) ^ (((holder_4) >>  3U) | ((holder_4) << 29U))) ^ ((state_2) ^ (uint32_t) (round_constant)[0U]); \
    (state_5) = ((holder_5) ^ (((holder_4) >>  1U) | ((holder_4) << 31U)) ^ (((holder_5) >>  3U) | ((holder_5) << 29U))) ^ ((state_3) ^ (uint32_t) (round_constant)[1U]); \
\
    (state_6) = (holder_6) ^ (((holder_6) >>  5U) | ((holder_6) << 27U)) ^ (((holder_7) >>  8U) | ((holder_7) << 24U)); \
    (state_7) = (holder_7) ^ (((holder_7) >>  5U) | ((holder_7) << 27U)) ^ (((holder_6) >>  9U) | ((holder_6) << 23U)); \
\
    (state_8) = (state_8) ^ (state_6); \
    (state_9) = (state_9) ^ (state_7); \
\
    (holder_0) = (state_0) ^ ((~(state_2)) & (state_4)); \
    (holder_1) = (state_1) ^ ((~(state_3)) & (state_5)); \
    (holder_2) = (state_2) ^ ((~(state_4)) & (state_6)) ^ (holder_0); \
    (holder_3) = (state_3) ^ ((~(state_5)) & (state_7)) ^ (holder_1); \
    (holder_4) = (state_4) ^ ((~(state_6)) & (state_8)); \
    (holder_5) = (state_5) ^ ((~(state_7)) & (state_9)); \
    (holder_6) = (state_6) ^ ((~(state_8)) & (state_0)) ^ (holder_4); \
    (holder_7) = (state_7) ^ ((~(state_9)) & (state_1)) ^ (holder_5); \
    (holder_8) = (state_8) ^ ((~(state_0)) & (state_2)); \
    (holder_9) = (state_9) ^ ((~(state_1)) & (state_3)); \
\
    (holder_0) = (holder_0) ^ (holder_8); \
    (holder_1) = (holder_1) ^ (holder_9); \
    (holder_4) = ~(holder_4); \
    (holder_5) = ~(holder_5); \
} while (0)
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
void VERUM_ASCON_permute_merged(uint32_t state[10U],
                                uint32_t holder[10U],
                                uint32_t round_constant);

#define VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                                   state_5, state_6, state_7, state_8, state_9, \
                                   holder_0, holder_1, holder_2, holder_3, holder_4, \
                                   holder_5, holder_6, holder_7, holder_8, holder_9, \
                                   round_constant) do { \
    (state_8) = (holder_8) ^ (((holder_8) >>  7U) | ((holder_9) << 25U)) ^ (((holder_8) << 23U) | ((holder_9) >> 9U)); \
    (state_9) = (holder_9) ^ (((holder_9) >>  7U) | ((holder_8) << 25U)) ^ (((holder_9) << 23U) | ((holder_8) >> 9U)); \
\
    (state_0) = ((holder_0) ^ (((holder_0) >> 19U) | ((holder_1) << 13U)) ^ (((holder_0) >> 28U) | ((holder_1) << 4U))) ^ (state_8); \
    (state_1) = ((holder_1) ^ (((holder_1) >> 19U) | ((holder_0) << 13U)) ^ (((holder_1) >> 28U) | ((holder_0) << 4U))) ^ (state_9); \
\
    (state_2) = (holder_2) ^ (((holder_2) << 3U) | ((holder_3) >> 29U)) ^ (((holder_2) << 25U) | ((holder_3) >> 7U)); \
    (state_3) = (holder_3) ^ (((holder_3) << 3U) | ((holder_2) >> 29U)) ^ (((holder_3) << 25U) | ((holder_2) >> 7U)); \
\
    (state_4) = ((holder_4) ^ (((holder_4) >>  1U) | ((holder_5) << 31U)) ^ (((holder_4) >>  6U) | ((holder_5) << 26U))) ^ ((state_2) ^ (round_constant)); \
    (state_5) = ((holder_5) ^ (((holder_5) >>  1U) | ((holder_4) << 31U)) ^ (((holder_5) >>  6U) | ((holder_4) << 26U))) ^ (state_3); \
\
    (state_6) = (holder_6) ^ (((holder_6) >> 10U) | ((holder_7) << 22U)) ^ (((holder_6) >> 17U) | ((holder_7) << 15U)); \
    (state_7) = (holder_7) ^ (((holder_7) >> 10U) | ((holder_6) << 22U)) ^ (((holder_7) >> 17U) | ((holder_6) << 15U)); \
\
    (state_8) = (state_8) ^ (state_6); \
    (state_9) = (state_9) ^ (state_7); \
\
    (holder_0) = (state_0) ^ ((~(state_2)) & (state_4)); \
    (holder_1) = (state_1) ^ ((~(state_3)) & (state_5)); \
    (holder_2) = (state_2) ^ ((~(state_4)) & (state_6)) ^ (holder_0); \
    (holder_3) = (state_3) ^ ((~(state_5)) & (state_7)) ^ (holder_1); \
    (holder_4) = (state_4) ^ ((~(state_6)) & (state_8)); \
    (holder_5) = (state_5) ^ ((~(state_7)) & (state_9)); \
    (holder_6) = (state_6) ^ ((~(state_8)) & (state_0)) ^ (holder_4); \
    (holder_7) = (state_7) ^ ((~(state_9)) & (state_1)) ^ (holder_5); \
    (holder_8) = (state_8) ^ ((~(state_0)) & (state_2)); \
    (holder_9) = (state_9) ^ ((~(state_1)) & (state_3)); \
\
    (holder_0) = (holder_0) ^ (holder_8); \
    (holder_1) = (holder_1) ^ (holder_9); \
    (holder_4) = ~(holder_4); \
    (holder_5) = ~(holder_5); \
} while (0)
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

#ifdef VERUM_ASCON_UNROLL_DEF

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
 * @details      Full 12-round unrolled permutation schedule (rounds 0..11) operating in
 *               place on twenty 32-bit register variables (state_0..state_9, holder_0..holder_9).
 *               Expands to the initial substitution layer (round 0), eleven fused
 *               diffusion-constant-substitution layers (rounds 1..11), and the final
 *               linear diffusion layer.
 * @optimization [OPT-A_5] Fused interior rounds eliminate inter-round state stores/loads.
 *               [OPT-A_7] Unrolled inline expansion eliminates loop-counter and branch overhead.
 *               [OPT-A_13] Operates directly on register-qualified scalars.
 */
#define VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4, \
                                state_5, state_6, state_7, state_8, state_9, \
                                holder_0, holder_1, holder_2, holder_3, holder_4, \
                                holder_5, holder_6, holder_7, holder_8, holder_9) do { \
    VERUM_ASCON_PERMUTE_SUBSTITUTION_LAYER(state_0, state_1, state_2, state_3, state_4, \
                                           state_5, state_6, state_7, state_8, state_9, \
                                           holder_0, holder_1, holder_2, holder_3, holder_4, \
                                           holder_5, holder_6, holder_7, holder_8, holder_9, \
                                           VERUM_ASCON_round_constants[0U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[1U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[2U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[3U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[4U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[5U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[6U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[7U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[8U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[9U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[10U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[11U]); \
    VERUM_ASCON_PERMUTE_LINEAR_DIFFUSION_LAYER(state_0, state_1, state_2, state_3, state_4, \
                                               state_5, state_6, state_7, state_8, state_9, \
                                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                                               holder_5, holder_6, holder_7, holder_8, holder_9); \
} while (0)

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8](S)
 * @details      Full 8-round unrolled permutation schedule (rounds 4..11) operating in
 *               place on twenty 32-bit register variables (state_0..state_9, holder_0..holder_9).
 *               Expands to the initial substitution layer (round 4), seven fused
 *               diffusion-constant-substitution layers (rounds 5..11), and the final
 *               linear diffusion layer.
 * @optimization [OPT-A_5] Fused interior rounds eliminate inter-round state stores/loads.
 *               [OPT-A_7] Unrolled inline expansion eliminates loop-counter and branch overhead.
 *               [OPT-A_13] Operates directly on register-qualified scalars.
 */
#define VERUM_ASCON_PERMUTE_P8(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9) do { \
    VERUM_ASCON_PERMUTE_SUBSTITUTION_LAYER(state_0, state_1, state_2, state_3, state_4, \
                                           state_5, state_6, state_7, state_8, state_9, \
                                           holder_0, holder_1, holder_2, holder_3, holder_4, \
                                           holder_5, holder_6, holder_7, holder_8, holder_9, \
                                           VERUM_ASCON_round_constants[4U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[5U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[6U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[7U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[8U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[9U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[10U]); \
    VERUM_ASCON_PERMUTE_MERGED(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9, \
                               VERUM_ASCON_round_constants[11U]); \
    VERUM_ASCON_PERMUTE_LINEAR_DIFFUSION_LAYER(state_0, state_1, state_2, state_3, state_4, \
                                               state_5, state_6, state_7, state_8, state_9, \
                                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                                               holder_5, holder_6, holder_7, holder_8, holder_9); \
} while (0)

#else /* VERUM_ASCON_UNROLL_DEF */

/**
 * @internal
 * @ref           NIST SP 800-232 Section 3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         Permutes the 320-bit ASCON state from @p round_index through round 11.
 * @param[in,out] state       320-bit state as ten 32-bit words.
 * @param[in]     round_index Starting round index (0 for Ascon-p[12], 4 for Ascon-p[8]).
 * @optimization  [OPT-A_6] Noinline and shared across p[12] and p[8]; peels the initial
 *                p_C+p_S and final p_L outside the loop so the body executes only fused
 *                p_L+p_C+p_S rounds in scalar registers, minimizing .text footprint and
 *                stack usage.
 */
void VERUM_ASCON_permute(uint32_t state[10U],
                         uint32_t round_index);

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S) (compact looped dispatch)
 * @details      Marshals the ten register-qualified state lanes (state_0..state_9)
 *               into the shared function-scoped @c state array and invokes the
 *               non-inlined VERUM_ASCON_permute subroutine starting at round 0.
 * @optimization [OPT-A_6] Reuses a single compact loop body and a single function-scoped
 *               state array across all p[12] and p[8] call sites when
 *               VERUM_OPTIMIZATION_MEMORY_DEF is active.
 */
#define VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4, \
                                state_5, state_6, state_7, state_8, state_9, \
                                holder_0, holder_1, holder_2, holder_3, holder_4, \
                                holder_5, holder_6, holder_7, holder_8, holder_9) do { \
    state[0U] = (state_0); state[1U] = (state_1); state[2U] = (state_2); \
    state[3U] = (state_3); state[4U] = (state_4); state[5U] = (state_5); \
    state[6U] = (state_6); state[7U] = (state_7); state[8U] = (state_8); \
    state[9U] = (state_9); \
    VERUM_ASCON_permute(state, 0U); \
    (state_0) = state[0U]; (state_1) = state[1U]; (state_2) = state[2U]; \
    (state_3) = state[3U]; (state_4) = state[4U]; (state_5) = state[5U]; \
    (state_6) = state[6U]; (state_7) = state[7U]; (state_8) = state[8U]; \
    (state_9) = state[9U]; \
} while (0)

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8](S) (compact looped dispatch)
 * @details      Marshals the ten register-qualified state lanes (state_0..state_9)
 *               into the shared function-scoped @c state array and invokes the
 *               non-inlined VERUM_ASCON_permute subroutine starting at round 4.
 * @optimization [OPT-A_6] Reuses a single compact loop body and a single function-scoped
 *               state array across all p[12] and p[8] call sites when
 *               VERUM_OPTIMIZATION_MEMORY_DEF is active.
 */
#define VERUM_ASCON_PERMUTE_P8(state_0, state_1, state_2, state_3, state_4, \
                               state_5, state_6, state_7, state_8, state_9, \
                               holder_0, holder_1, holder_2, holder_3, holder_4, \
                               holder_5, holder_6, holder_7, holder_8, holder_9) do { \
    state[0U] = (state_0); state[1U] = (state_1); state[2U] = (state_2); \
    state[3U] = (state_3); state[4U] = (state_4); state[5U] = (state_5); \
    state[6U] = (state_6); state[7U] = (state_7); state[8U] = (state_8); \
    state[9U] = (state_9); \
    VERUM_ASCON_permute(state, 4U); \
    (state_0) = state[0U]; (state_1) = state[1U]; (state_2) = state[2U]; \
    (state_3) = state[3U]; (state_4) = state[4U]; (state_5) = state[5U]; \
    (state_6) = state[6U]; (state_7) = state[7U]; (state_8) = state[8U]; \
    (state_9) = state[9U]; \
} while (0)

#endif /* VERUM_ASCON_UNROLL_DEF */

#ifdef VERUM_STANDARD_FIPS_140_3_DEF
#ifdef VERUM_FAULT_HANDLER_DEF
#else /* VERUM_FAULT_HANDLER_DEF */
// cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 _Noreturn function attribute is required for safety-critical fault handlers.
VERUM_ATTR_NORETURN void VERUM_FAULT_HANDLER_DEF(void);
#endif /* VERUM_FAULT_HANDLER_DEF */

/**
 * @enum      VERUM_FIPS1403_state_t
 * @brief     FIPS 140-3 module operational states (ISO/IEC 19790:2012 Section 7.4).
 */
typedef enum
{
    VERUM_FIPS1403_STATE_UNINITIALIZED = 0, /**< Module power-on / uninitialized state. */
    VERUM_FIPS1403_STATE_INITIALIZING  = 1, /**< Pre-operational self-test (KAT) running. */
    VERUM_FIPS1403_STATE_OPERATIONAL   = 2, /**< Self-tests passed, operational approved state. */
    VERUM_FIPS1403_STATE_ERROR         = 3  /**< Error state: all data output interfaces inhibited. */
} VERUM_FIPS1403_state_t;
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */

#endif /* VERUM_ASCON_H_ */
