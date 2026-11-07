/**
 * @file      bench_ascon.c
 * @brief     Comprehensive Ascon suite benchmarks for bare-metal targets.
 * @details   Benchmarks Ascon-p[12], AEAD128 (encrypt/decrypt), Hash256,
 *            XOF128, and CXOF128 with cycle/instruction counts and stack watermarking.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */

#include "bench_ascon.h"
#include "harness/perf.h"
#include "harness/semihost.h"
#include "verum/ascon/aead.h"
#include "verum/ascon/hash.h"
#include "verum/ascon/xof.h"
#include "verum/ascon/cxof.h"
#include "macro.h"
#include "ascon.h"

#define BENCH_DATA_SIZE 32U

static int mem_equal(const uint8_t *a,
                     const uint8_t *b,
                     uint32_t len)
{
    uint8_t diff = 0U;
    for (uint32_t i = 0U; i < len; i++)
    {
        diff |= (uint8_t) (a[i] ^ b[i]);
    }
    return (diff == 0U) ? 1 : 0;
}

static void emit_metric(const char *op,
                        uint32_t bytes,
                        uint32_t cycles,
                        uint32_t insns,
                        uint32_t peak_stack,
                        const char *status)
{
    semihost_puts("BENCH:op=");
    semihost_puts(op);
    semihost_puts(",bytes=");
    semihost_put_u32(bytes);
    semihost_puts(",cycles=");
    semihost_put_u32(cycles);
    semihost_puts(",insns=");
    semihost_put_u32(insns);
    semihost_puts(",peak_stack=");
    semihost_put_u32(peak_stack);
    semihost_puts(",status=");
    semihost_puts(status);
    semihost_puts("\n");
}

VERUM_ATTR_NOINLINE static void run_p12(uint32_t state[10U],
                                        uint32_t holder[10U])
{
#ifdef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[0U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[1U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[2U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[3U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[4U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#else /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
    VERUM_ASCON_permute(state, holder, 0U);
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
}

VERUM_ATTR_NOINLINE static void run_p8(uint32_t state[10U],
                                       uint32_t holder[10U])
{
#ifdef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[4U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#else /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
    VERUM_ASCON_permute(state, holder, 4U);
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
}

/* --- 1a. Ascon-p[12] Permutation Benchmark --- */
static int bench_permute_p12(void)
{
    uint32_t state[10U] = { 0U };
    uint32_t holder[10U] = { 0U };

    run_p12(state, holder); /* warm-up */

    perf_stack_paint();
    uint32_t sp_before = perf_get_sp();
    uint32_t t_start = perf_cycles_read();
    uint32_t i_start = perf_insn_read();

    run_p12(state, holder);

    uint32_t i_stop = perf_insn_read();
    uint32_t t_stop = perf_cycles_read();
    uint32_t peak_stack = perf_stack_peak(sp_before);

    uint32_t cyc = perf_cycles_diff(t_start, t_stop);
    uint32_t insn = perf_insn_diff(i_start, i_stop);

    /* State after p12 on all-zeros must be non-zero due to round constants */
    uint32_t accum = 0U;
    for (uint32_t i = 0U; i < 10U; i++)
    {
        accum |= state[i];
    }
    const char *status = (accum != 0U) ? "PASSED" : "FAILED";

    emit_metric("p12", 0U, cyc, insn, peak_stack, status);
    return (accum != 0U) ? 0 : 1;
}

/* --- 1b. Ascon-p[8] Permutation Benchmark --- */
static int bench_permute_p8(void)
{
    uint32_t state[10U] = { 0U };
    uint32_t holder[10U] = { 0U };

    run_p8(state, holder); /* warm-up */

    perf_stack_paint();
    uint32_t sp_before = perf_get_sp();
    uint32_t t_start = perf_cycles_read();
    uint32_t i_start = perf_insn_read();

    run_p8(state, holder);

    uint32_t i_stop = perf_insn_read();
    uint32_t t_stop = perf_cycles_read();
    uint32_t peak_stack = perf_stack_peak(sp_before);

    uint32_t cyc = perf_cycles_diff(t_start, t_stop);
    uint32_t insn = perf_insn_diff(i_start, i_stop);

    /* State after p8 on all-zeros must be non-zero due to round constants */
    uint32_t accum = 0U;
    for (uint32_t i = 0U; i < 10U; i++)
    {
        accum |= state[i];
    }
    const char *status = (accum != 0U) ? "PASSED" : "FAILED";

    emit_metric("p8", 0U, cyc, insn, peak_stack, status);
    return (accum != 0U) ? 0 : 1;
}

/* --- 2. Ascon-AEAD128 Encrypt and Decrypt Benchmarks --- */
static int bench_aead128(void)
{
#ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    const uint32_t key[4U] = { 0x32321010UL, 0x11001100UL, 0x32321010UL, 0x33223322UL };
    const uint32_t nonce[4U] = { 0x32321010UL, 0x11001100UL, 0x32321010UL, 0x33223322UL };
    const uint32_t *key_param = key;
    const uint32_t *nonce_param = nonce;
#else /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
    const uint8_t key[16U] = {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] = {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint32_t *key_param = (const uint32_t *) key;
    const uint32_t *nonce_param = (const uint32_t *) nonce;
#endif /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[14U] = {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU
    };
    const uint8_t expected_ciphertext[BENCH_DATA_SIZE] = {
        0x4EU, 0x58U, 0x92U, 0x70U, 0xFEU, 0xB8U, 0x9BU, 0xB2U,
        0x24U, 0x08U, 0x04U, 0x1DU, 0xAFU, 0x7DU, 0x55U, 0xDBU,
        0x9BU, 0xA1U, 0x25U, 0xD4U, 0xD1U, 0xE5U, 0x8FU, 0x75U,
        0xBDU, 0x9BU, 0xDEU, 0x4BU, 0xDAU, 0x18U, 0xC0U, 0x79U
    };
    const uint8_t expected_tag[16U] = {
        0x33U, 0x84U, 0xBDU, 0xE5U, 0x17U, 0x81U, 0xCFU, 0xECU,
        0x7EU, 0xC9U, 0xCEU, 0x69U, 0x61U, 0x82U, 0x70U, 0x63U
    };
#else /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
    const uint8_t expected_ciphertext[BENCH_DATA_SIZE] = {
        0xE7U, 0x70U, 0xD2U, 0x89U, 0xD2U, 0xA4U, 0x4AU, 0xEEU,
        0x7CU, 0xD0U, 0xA4U, 0x8EU, 0xCEU, 0x52U, 0x74U, 0xE3U,
        0x81U, 0xBAU, 0xD7U, 0xE1U, 0x63U, 0xDCU, 0xC4U, 0x97U,
        0x0FU, 0x78U, 0x73U, 0x61U, 0x0DU, 0xEBU, 0xBEU, 0xB1U
    };
    const uint8_t expected_tag[16U] = {
        0xA2U, 0x86U, 0x57U, 0xF6U, 0xE8U, 0x2FU, 0xE5U, 0x3DU,
        0x08U, 0xB0U, 0x9EU, 0xFFU, 0x93U, 0x30U, 0xBDU, 0x2BU
    };
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */

    uint32_t buf_words[8U];
    uint8_t *buffer = (uint8_t *) buf_words;
    for (uint32_t i = 0U; i < BENCH_DATA_SIZE; i++)
    {
        buffer[i] = (uint8_t) i;
    }
    uint32_t tag[4U] = { 0U };

    /* 2a. AEAD128 Encrypt */
    perf_stack_paint();
    uint32_t sp_enc = perf_get_sp();
    uint32_t t_enc_start = perf_cycles_read();
    uint32_t i_enc_start = perf_insn_read();

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    VERUM_ASCON_AEAD128_encrypt(key_param,
                                nonce_param,
                                buffer,
                                BENCH_DATA_SIZE,
                                associated_data,
                                14U,
                                tag);
#else /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
    VERUM_ASCON_AEAD128_encrypt(key_param,
                                nonce_param,
                                buffer,
                                BENCH_DATA_SIZE,
                                tag);
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */

    uint32_t i_enc_stop = perf_insn_read();
    uint32_t t_enc_stop = perf_cycles_read();
    uint32_t peak_enc = perf_stack_peak(sp_enc);

    uint32_t cyc_enc = perf_cycles_diff(t_enc_start, t_enc_stop);
    uint32_t insn_enc = perf_insn_diff(i_enc_start, i_enc_stop);

    int ct_match = mem_equal(buffer, expected_ciphertext, BENCH_DATA_SIZE);
    int tag_match = mem_equal((const uint8_t *) tag, expected_tag, 16U);
    const char *status_enc = (ct_match && tag_match) ? "PASSED" : "FAILED";

    emit_metric("aead_enc", BENCH_DATA_SIZE, cyc_enc, insn_enc, peak_enc, status_enc);

    /* 2b. AEAD128 Decrypt */
    uint32_t dec_tag[4U] = { 0U };
    perf_stack_paint();
    uint32_t sp_dec = perf_get_sp();
    uint32_t t_dec_start = perf_cycles_read();
    uint32_t i_dec_start = perf_insn_read();

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    VERUM_ASCON_AEAD128_decrypt(key_param,
                                nonce_param,
                                buffer,
                                BENCH_DATA_SIZE,
                                associated_data,
                                14U,
                                dec_tag);
#else /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
    VERUM_ASCON_AEAD128_decrypt(key_param,
                                nonce_param,
                                buffer,
                                BENCH_DATA_SIZE,
                                dec_tag);
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */

    uint32_t i_dec_stop = perf_insn_read();
    uint32_t t_dec_stop = perf_cycles_read();
    uint32_t peak_dec = perf_stack_peak(sp_dec);

    uint32_t cyc_dec = perf_cycles_diff(t_dec_start, t_dec_stop);
    uint32_t insn_dec = perf_insn_diff(i_dec_start, i_dec_stop);

    uint8_t expected_pt[BENCH_DATA_SIZE];
    for (uint32_t i = 0U; i < BENCH_DATA_SIZE; i++)
    {
        expected_pt[i] = (uint8_t) i;
    }
    int pt_match = mem_equal(buffer, expected_pt, BENCH_DATA_SIZE);
    int dec_tag_match = mem_equal((const uint8_t *) dec_tag, expected_tag, 16U);
    const char *status_dec = (pt_match && dec_tag_match) ? "PASSED" : "FAILED";

    emit_metric("aead_dec", BENCH_DATA_SIZE, cyc_dec, insn_dec, peak_dec, status_dec);

    return (ct_match && tag_match && pt_match && dec_tag_match) ? 0 : 1;
}

/* --- 3. Ascon-Hash256 Benchmark --- */
static int bench_hash256(void)
{
    uint32_t msg_words[8U];
    uint8_t *message = (uint8_t *) msg_words;
    for (uint32_t i = 0U; i < BENCH_DATA_SIZE; i++)
    {
        message[i] = (uint8_t) i;
    }
    uint32_t digest[8U] = { 0U };

    const uint8_t expected_hash[32U] = {
        0xBDU, 0x9DU, 0x3DU, 0x60U, 0xA6U, 0x6BU, 0x53U, 0x86U,
        0x8EU, 0xABU, 0x2AU, 0x5CU, 0x74U, 0x53U, 0x9AU, 0x51U,
        0x8AU, 0x1FU, 0x60U, 0xF0U, 0x1EU, 0xB1U, 0x76U, 0xC6U,
        0x0EU, 0x43U, 0xDEU, 0xE8U, 0x16U, 0x80U, 0xB3U, 0x3EU
    };

    VERUM_ASCON_HASH256_digest(message, BENCH_DATA_SIZE, digest); /* warm-up */

    perf_stack_paint();
    uint32_t sp = perf_get_sp();
    uint32_t t_start = perf_cycles_read();
    uint32_t i_start = perf_insn_read();

    VERUM_ASCON_HASH256_digest(message, BENCH_DATA_SIZE, digest);

    uint32_t i_stop = perf_insn_read();
    uint32_t t_stop = perf_cycles_read();
    uint32_t peak = perf_stack_peak(sp);

    uint32_t cyc = perf_cycles_diff(t_start, t_stop);
    uint32_t insn = perf_insn_diff(i_start, i_stop);

    int match = mem_equal((const uint8_t *) digest, expected_hash, 32U);
    const char *status = match ? "PASSED" : "FAILED";

    emit_metric("hash256", BENCH_DATA_SIZE, cyc, insn, peak, status);
    return match ? 0 : 1;
}

/* --- 4. Ascon-XOF128 Benchmark --- */
static int bench_xof128(void)
{
    uint32_t msg_words[8U];
    uint8_t *message = (uint8_t *) msg_words;
    for (uint32_t i = 0U; i < BENCH_DATA_SIZE; i++)
    {
        message[i] = (uint8_t) i;
    }
    uint8_t digest[17U] __attribute__((aligned(4))) = { 0U };

    const uint8_t expected_xof[17U] = {
        0x2EU, 0x5FU, 0x34U, 0x03U, 0xF4U, 0x17U, 0x14U, 0x71U,
        0xCCU, 0x79U, 0x34U, 0xB5U, 0x19U, 0x82U, 0xCEU, 0xCEU,
        0x8DU
    };

    VERUM_ASCON_XOF128_digest(message, BENCH_DATA_SIZE, digest, 17U); /* warm-up */

    perf_stack_paint();
    uint32_t sp = perf_get_sp();
    uint32_t t_start = perf_cycles_read();
    uint32_t i_start = perf_insn_read();

    VERUM_ASCON_XOF128_digest(message, BENCH_DATA_SIZE, digest, 17U);

    uint32_t i_stop = perf_insn_read();
    uint32_t t_stop = perf_cycles_read();
    uint32_t peak = perf_stack_peak(sp);

    uint32_t cyc = perf_cycles_diff(t_start, t_stop);
    uint32_t insn = perf_insn_diff(i_start, i_stop);

    int match = mem_equal(digest, expected_xof, 17U);
    const char *status = match ? "PASSED" : "FAILED";

    emit_metric("xof128", BENCH_DATA_SIZE, cyc, insn, peak, status);
    return match ? 0 : 1;
}

/* --- 5. Ascon-CXOF128 Benchmark --- */
static int bench_cxof128(void)
{
    uint32_t msg_words[8U];
    uint8_t *message = (uint8_t *) msg_words;
    for (uint32_t i = 0U; i < BENCH_DATA_SIZE; i++)
    {
        message[i] = (uint8_t) i;
    }
    const uint8_t customization[2U] __attribute__((aligned(4))) = { 0x00U, 0x01U };
    uint8_t digest[32U] __attribute__((aligned(4))) = { 0U };

    const uint8_t expected_cxof[32U] = {
        0x4DU, 0x7FU, 0x86U, 0x48U, 0xA2U, 0xC7U, 0x21U, 0x96U,
        0xEBU, 0x19U, 0x79U, 0x4CU, 0x9DU, 0x1BU, 0xC1U, 0xB4U,
        0xCCU, 0xE3U, 0xACU, 0xCEU, 0x52U, 0xF1U, 0xA8U, 0x83U,
        0x1AU, 0x19U, 0xF2U, 0x80U, 0x4CU, 0xE6U, 0x24U, 0xF4U
    };

    VERUM_ASCON_CXOF128_digest(message, BENCH_DATA_SIZE, customization, 2U, digest, 32U); /* warm-up */

    perf_stack_paint();
    uint32_t sp = perf_get_sp();
    uint32_t t_start = perf_cycles_read();
    uint32_t i_start = perf_insn_read();

    VERUM_ASCON_CXOF128_digest(message, BENCH_DATA_SIZE, customization, 2U, digest, 32U);

    uint32_t i_stop = perf_insn_read();
    uint32_t t_stop = perf_cycles_read();
    uint32_t peak = perf_stack_peak(sp);

    uint32_t cyc = perf_cycles_diff(t_start, t_stop);
    uint32_t insn = perf_insn_diff(i_start, i_stop);

    int match = mem_equal(digest, expected_cxof, 32U);
    const char *status = match ? "PASSED" : "FAILED";

    emit_metric("cxof128", BENCH_DATA_SIZE, cyc, insn, peak, status);
    return match ? 0 : 1;
}

#ifdef VERUM_STANDARD_FIPS_140_3_DEF
/* --- 6. FIPS 140-3 Power-On Self-Test (POST) Benchmarks --- */
static int bench_fips_self_test(void)
{
    perf_stack_paint();
    uint32_t sp = perf_get_sp();
    uint32_t t_start = perf_cycles_read();
    uint32_t i_start = perf_insn_read();

    int rc = 0;
    rc |= (VERUM_FIPS1403_ASCON_AEAD128_self_test() != 0);
    rc |= (VERUM_FIPS1403_ASCON_HASH256_self_test() != 0);
    rc |= (VERUM_FIPS1403_ASCON_XOF128_self_test() != 0);
    rc |= (VERUM_FIPS1403_ASCON_CXOF128_self_test() != 0);

    uint32_t i_stop = perf_insn_read();
    uint32_t t_stop = perf_cycles_read();
    uint32_t peak = perf_stack_peak(sp);

    uint32_t cyc = perf_cycles_diff(t_start, t_stop);
    uint32_t insn = perf_insn_diff(i_start, i_stop);

    const char *status = (rc == 0) ? "PASSED" : "FAILED";

    emit_metric("fips_post", 0U, cyc, insn, peak, status);
    return rc;
}
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */

int bench_ascon_run(void)
{
    int rc = 0;

#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    rc |= bench_fips_self_test();
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */
    rc |= bench_permute_p12();
    rc |= bench_permute_p8();
    rc |= bench_aead128();
    rc |= bench_hash256();
    rc |= bench_xof128();
    rc |= bench_cxof128();

    return rc;
}
