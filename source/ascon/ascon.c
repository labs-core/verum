/**
 * @file      ascon.c
 * @brief     Ascon shared permutation primitives.
 * @details   Implements shared round constants, bit-interleaving conversions, and 320-bit
 *            Ascon-p permutation layers over the bit-interleaved state [OPT-A_0]
 *            (state[2w] = E_w, state[2w+1] = O_w) using explicit 32-bit operations
 *            (NIST SP 800-232 Section 3).
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

 #include "ascon.h"

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3.2 Table 5
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        C[𝑖] = Const[16−𝑟𝑛𝑑+𝑖]
 * @details      π(C[𝑖]) = { E, O } of 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
 *               0x78, 0x69, 0x5A, 0x4B; XORed into S2 as state[4U] ^= E, state[5U] ^= O.
 * @optimization [OPT-A_2] Pre-interleaved uint8_t pairs: 24 B .rodata, no runtime π.
 */
const uint8_t VERUM_ASCON_round_constants[12U][2U] = {
    { 0x0CU, 0x0CU }, { 0x09U, 0x0CU }, { 0x0CU, 0x09U }, { 0x09U, 0x09U },
    { 0x06U, 0x0CU }, { 0x03U, 0x0CU }, { 0x06U, 0x09U }, { 0x03U, 0x09U },
    { 0x0CU, 0x06U }, { 0x09U, 0x06U }, { 0x0CU, 0x03U }, { 0x09U, 0x03U }
};

/**
 * @internal
 * @brief         π: (𝐿, 𝐻) → (𝐸, 𝑂), in place.
 * @param[in,out] word Entry: { 𝐿, 𝐻 } little-endian halves. Return: { 𝐸, 𝑂 }.
 * @optimization  [OPT-A_14] Delta swap t = (x ^ (x >> n)) & m; x ^= t ^ (t << n) exchanges
 *                bit groups in 3+3 ops. Stages n = 1, 2, 4, 8 sort each half into
 *                [odd16 | even16]; the final merge packs both halves' even bits into 𝐸 and
 *                odd bits into 𝑂 preserving bit order (𝐸 bit k = S bit 2k, 𝑂 bit k = S bit 2k+1).
 */
void VERUM_ASCON_interleave(uint32_t word[2U])
{
    uint32_t delta = (word[0U] ^ (word[0U] >> 1U)) & 0x22222222UL;
    word[0U] = word[0U] ^ delta ^ (delta << 1U);
    delta = (word[0U] ^ (word[0U] >> 2U)) & 0x0C0C0C0CUL;
    word[0U] = word[0U] ^ delta ^ (delta << 2U);
    delta = (word[0U] ^ (word[0U] >> 4U)) & 0x00F000F0UL;
    word[0U] = word[0U] ^ delta ^ (delta << 4U);
    delta = (word[0U] ^ (word[0U] >> 8U)) & 0x0000FF00UL;
    word[0U] = word[0U] ^ delta ^ (delta << 8U);

    delta = (word[1U] ^ (word[1U] >> 1U)) & 0x22222222UL;
    word[1U] = word[1U] ^ delta ^ (delta << 1U);
    delta = (word[1U] ^ (word[1U] >> 2U)) & 0x0C0C0C0CUL;
    word[1U] = word[1U] ^ delta ^ (delta << 2U);
    delta = (word[1U] ^ (word[1U] >> 4U)) & 0x00F000F0UL;
    word[1U] = word[1U] ^ delta ^ (delta << 4U);
    delta = (word[1U] ^ (word[1U] >> 8U)) & 0x0000FF00UL;
    word[1U] = word[1U] ^ delta ^ (delta << 8U);

    delta = (word[0U] & 0x0000FFFFUL) | (word[1U] << 16U);
    word[1U] = (word[0U] >> 16U) | (word[1U] & 0xFFFF0000UL);
    word[0U] = delta;
}

/**
 * @internal
 * @brief         π⁻¹: (𝐸, 𝑂) → (𝐿, 𝐻), in place.
 * @param[in,out] word Entry: { 𝐸, 𝑂 }. Return: { 𝐿, 𝐻 } little-endian halves.
 * @optimization  [OPT-A_14] 16-bit split, then π's self-inverse delta swaps in reverse
 *                order (n = 8, 4, 2, 1).
 */
void VERUM_ASCON_deinterleave(uint32_t word[2U])
{
    uint32_t delta = (word[0U] & 0x0000FFFFUL) | (word[1U] << 16U);
    word[1U] = (word[0U] >> 16U) | (word[1U] & 0xFFFF0000UL);
    word[0U] = delta;

    delta = (word[0U] ^ (word[0U] >> 8U)) & 0x0000FF00UL;
    word[0U] = word[0U] ^ delta ^ (delta << 8U);
    delta = (word[0U] ^ (word[0U] >> 4U)) & 0x00F000F0UL;
    word[0U] = word[0U] ^ delta ^ (delta << 4U);
    delta = (word[0U] ^ (word[0U] >> 2U)) & 0x0C0C0C0CUL;
    word[0U] = word[0U] ^ delta ^ (delta << 2U);
    delta = (word[0U] ^ (word[0U] >> 1U)) & 0x22222222UL;
    word[0U] = word[0U] ^ delta ^ (delta << 1U);

    delta = (word[1U] ^ (word[1U] >> 8U)) & 0x0000FF00UL;
    word[1U] = word[1U] ^ delta ^ (delta << 8U);
    delta = (word[1U] ^ (word[1U] >> 4U)) & 0x00F000F0UL;
    word[1U] = word[1U] ^ delta ^ (delta << 4U);
    delta = (word[1U] ^ (word[1U] >> 2U)) & 0x0C0C0C0CUL;
    word[1U] = word[1U] ^ delta ^ (delta << 2U);
    delta = (word[1U] ^ (word[1U] >> 1U)) & 0x22222222UL;
    word[1U] = word[1U] ^ delta ^ (delta << 1U);
}

/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2 and 3.3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @param[in,out] state          320-bit bit-interleaved state as ten 32-bit words.
 * @param[out]    holder         320-bit scratch buffer receiving post-S-box words.
 * @param[in]     round_constant Bit-interleaved round constant π(C[i]) = { E, O }.
 * @details       π preserves ⊕, ∧, ¬, so the S-box runs identically on E lanes (even
 *                indices) and O lanes (odd indices) with no cross-lane traffic.
 */
VERUM_ATTR_INLINE
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
static
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
inline void VERUM_ASCON_permute_substitution_layer(uint32_t state[10U],
                                                                  uint32_t holder[10U],
                                                                  const uint8_t round_constant[2U])
{
    state[0U] = state[0U] ^ state[8U];
    state[1U] = state[1U] ^ state[9U];
    /**
     * @internal
     * @ref          NIST SP 800-232 Section 3.2
     * @brief        𝑝𝐶 Constant-Addition Layer: S2 ← S2 ⊕ C[𝑖]
     * @optimization [OPT-A_3] Folded into the S2 ^= S1 pre-mix, saving a separate
     *               read-modify-write on state[4U] and state[5U].
     */
    state[4U] = state[4U] ^ state[2U] ^ (uint32_t) round_constant[0U];
    state[5U] = state[5U] ^ state[3U] ^ (uint32_t) round_constant[1U];

    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 3.3
     * @brief        𝑝𝑆 Substitution Layer
     * @optimization [OPT-A_4] (~x) & y and ~x replace (x ^ 0xFFFFFFFFUL) & y and
     *               x ^ 0xFFFFFFFFUL, mapping to single-cycle NOT-AND (BIC/ANDN) and NOT,
     *               removing 12 immediate XORs per round.
     */
    holder[0U] = state[0U] ^ ((~state[2U]) & state[4U]);
    holder[1U] = state[1U] ^ ((~state[3U]) & state[5U]);
    holder[2U] = state[2U] ^ ((~state[4U]) & state[6U]) ^ holder[0U];
    holder[3U] = state[3U] ^ ((~state[5U]) & state[7U]) ^ holder[1U];
    holder[4U] = state[4U] ^ ((~state[6U]) & state[8U]);
    holder[5U] = state[5U] ^ ((~state[7U]) & state[9U]);
    holder[6U] = state[6U] ^ ((~state[8U]) & state[0U]) ^ holder[4U];
    holder[7U] = state[7U] ^ ((~state[9U]) & state[1U]) ^ holder[5U];
    holder[8U] = state[8U] ^ ((~state[0U]) & state[2U]);
    holder[9U] = state[9U] ^ ((~state[1U]) & state[3U]);


    holder[0U] = holder[0U] ^ holder[8U];
    holder[1U] = holder[1U] ^ holder[9U];
    holder[4U] = ~holder[4U];
    holder[5U] = ~holder[5U];
}

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3.4
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        𝑝𝐿 Linear Diffusion Layer: Σ𝑤(S𝑤) = S𝑤 ⊕ (S𝑤 ⋙ 𝑟1) ⊕ (S𝑤 ⋙ 𝑟2)
 * @param[out]   state  320-bit bit-interleaved state receiving diffused words.
 * @param[in]    holder 320-bit scratch buffer holding post-substitution words.
 * @optimization [OPT-A_1] Bit-interleaved 64-bit rotations (see [OPT-A_0]). Converts 20 cross-register
 *               funnel shifts into 19 single-register RORs, fusing into XOR (EOR Rd, Rn, Rm, ROR #k).
 *               Parity mapping (WARREN JR., 2012; DOBRAUNIG et al., 2021):
 *                 π(S ⋙ 2k)     = (E ⋙ k, O ⋙ k)
 *                 π(S ⋙ 2k + 1) = (O ⋙ k, E ⋙ (k + 1))  [cross-lane swap: odd bit -> even lane]
 *               Word map r -> (E', O'):
 *                 Σ0 (19, 28): (O⋙9 ^ E⋙14,  E⋙10 ^ O⋙14)
 *                 Σ1 (61, 39): (O⋙30 ^ O⋙19, E⋙31 ^ E⋙20)
 *                 Σ2 ( 1,  6): (O ^ E⋙3,     E⋙1 ^ O⋙3)   [r=1 => k=0: O unrotated]
 *                 Σ3 (10, 17): (E⋙5 ^ O⋙8,   O⋙5 ^ E⋙9)
 *                 Σ4 ( 7, 41): (O⋙3 ^ O⋙20,  E⋙4 ^ E⋙21)
 */
VERUM_ATTR_INLINE
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
static
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
inline void VERUM_ASCON_permute_linear_diffusion_layer(uint32_t state[10U],
                                                                      const uint32_t holder[10U])
{
    state[0U] = holder[0U] ^ ((holder[1U] >>  9U) | (holder[1U] << 23U)) ^ ((holder[0U] >> 14U) | (holder[0U] << 18U));
    state[1U] = holder[1U] ^ ((holder[0U] >> 10U) | (holder[0U] << 22U)) ^ ((holder[1U] >> 14U) | (holder[1U] << 18U));

    state[2U] = holder[2U] ^ ((holder[3U] >> 30U) | (holder[3U] <<  2U)) ^ ((holder[3U] >> 19U) | (holder[3U] << 13U));
    state[3U] = holder[3U] ^ ((holder[2U] >> 31U) | (holder[2U] <<  1U)) ^ ((holder[2U] >> 20U) | (holder[2U] << 12U));

    state[4U] = holder[4U] ^ holder[5U] ^ ((holder[4U] >>  3U) | (holder[4U] << 29U));
    state[5U] = holder[5U] ^ ((holder[4U] >>  1U) | (holder[4U] << 31U)) ^ ((holder[5U] >>  3U) | (holder[5U] << 29U));

    state[6U] = holder[6U] ^ ((holder[6U] >>  5U) | (holder[6U] << 27U)) ^ ((holder[7U] >>  8U) | (holder[7U] << 24U));
    state[7U] = holder[7U] ^ ((holder[7U] >>  5U) | (holder[7U] << 27U)) ^ ((holder[6U] >>  9U) | (holder[6U] << 23U));

    state[8U] = holder[8U] ^ ((holder[9U] >>  3U) | (holder[9U] << 29U)) ^ ((holder[9U] >> 20U) | (holder[9U] << 12U));
    state[9U] = holder[9U] ^ ((holder[8U] >>  4U) | (holder[8U] << 28U)) ^ ((holder[8U] >> 21U) | (holder[8U] << 11U));
}

/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2, 3.3, and 3.4
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐿 Linear Diffusion Layer; 𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @param[out]    state          320-bit bit-interleaved state buffer.
 * @param[in,out] holder         320-bit scratch buffer updated across merged rounds.
 * @param[in]     round_constant Bit-interleaved round constant π(C[i]) = { E, O }.
 * @optimization  [OPT-A_5] Fuses p_L of round i-1 with p_C and p_S of round i, diffusing
 *                S4 (state[8U..9U]) and S2 (state[4U..5U]) ahead of S0 and S3 so the
 *                S-box pre-mix (S0 ^= S4, S2 ^= S1 ^ C[i], S4 ^= S3) folds into the
 *                diffusion stores, eliminating inter-round state loads and stores.
 *                [OPT-A_1] p_L uses the bit-interleaved rotation map of
 *                VERUM_ASCON_permute_linear_diffusion_layer.
 */
VERUM_ATTR_INLINE
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
static
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
inline void VERUM_ASCON_permute_merged(uint32_t state[10U],
                                                      uint32_t holder[10U],
                                                      const uint8_t round_constant[2U])
{
    state[8U] = holder[8U] ^ ((holder[9U] >>  3U) | (holder[9U] << 29U)) ^ ((holder[9U] >> 20U) | (holder[9U] << 12U));
    state[9U] = holder[9U] ^ ((holder[8U] >>  4U) | (holder[8U] << 28U)) ^ ((holder[8U] >> 21U) | (holder[8U] << 11U));

    state[0U] = (holder[0U] ^ ((holder[1U] >>  9U) | (holder[1U] << 23U)) ^ ((holder[0U] >> 14U) | (holder[0U] << 18U))) ^ state[8U];
    state[1U] = (holder[1U] ^ ((holder[0U] >> 10U) | (holder[0U] << 22U)) ^ ((holder[1U] >> 14U) | (holder[1U] << 18U))) ^ state[9U];

    state[2U] = holder[2U] ^ ((holder[3U] >> 30U) | (holder[3U] <<  2U)) ^ ((holder[3U] >> 19U) | (holder[3U] << 13U));
    state[3U] = holder[3U] ^ ((holder[2U] >> 31U) | (holder[2U] <<  1U)) ^ ((holder[2U] >> 20U) | (holder[2U] << 12U));

    /**
     * @internal
     * @optimization [OPT-A_3] p_C (S2 ^= C[i]) folded into the S2 ^= S1 pre-mix.
     */
    state[4U] = (holder[4U] ^ holder[5U] ^ ((holder[4U] >>  3U) | (holder[4U] << 29U))) ^ (state[2U] ^ (uint32_t) round_constant[0U]);
    state[5U] = (holder[5U] ^ ((holder[4U] >>  1U) | (holder[4U] << 31U)) ^ ((holder[5U] >>  3U) | (holder[5U] << 29U))) ^ (state[3U] ^ (uint32_t) round_constant[1U]);

    state[6U] = holder[6U] ^ ((holder[6U] >>  5U) | (holder[6U] << 27U)) ^ ((holder[7U] >>  8U) | (holder[7U] << 24U));
    state[7U] = holder[7U] ^ ((holder[7U] >>  5U) | (holder[7U] << 27U)) ^ ((holder[6U] >>  9U) | (holder[6U] << 23U));


    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 3.3
     * @brief        𝑝𝑆 Substitution Layer
     * @optimization [OPT-A_4] NOT-AND (~x) & y and ~x (see substitution layer).
     */
    holder[0U] = state[0U] ^ ((~state[2U]) & state[4U]);
    holder[1U] = state[1U] ^ ((~state[3U]) & state[5U]);
    holder[2U] = state[2U] ^ ((~state[4U]) & state[6U]) ^ holder[0U];
    holder[3U] = state[3U] ^ ((~state[5U]) & state[7U]) ^ holder[1U];
    holder[4U] = state[4U] ^ ((~state[6U]) & state[8U]);
    holder[5U] = state[5U] ^ ((~state[7U]) & state[9U]);
    holder[6U] = state[6U] ^ ((~state[8U]) & state[0U]) ^ holder[4U];
    holder[7U] = state[7U] ^ ((~state[9U]) & state[1U]) ^ holder[5U];
    holder[8U] = state[8U] ^ ((~state[0U]) & state[2U]);
    holder[9U] = state[9U] ^ ((~state[1U]) & state[3U]);


    holder[0U] = holder[0U] ^ holder[8U];
    holder[1U] = holder[1U] ^ holder[9U];
    holder[4U] = ~holder[4U];
    holder[5U] = ~holder[5U];
}


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
VERUM_ATTR_NOINLINE
void VERUM_ASCON_permute(uint32_t state[10U],
                                        uint32_t * const holder,
                                        uint32_t round_index)
{
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[round_index]);
    ++round_index;
    do
    {
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[round_index]);
        ++round_index;
    }
    while (round_index < 12U);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
}

#endif // VERUM_OPTIMIZATION_MEMORY_DEF
