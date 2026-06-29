#!/usr/bin/env python3

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from _common import (
    KAT_AEAD, OUT_AEAD,
    fmt_array_body, fmt_byte, hex_abbrev, num_to_words,
)

_FILE_HEADER = """\
/**
 * @file      aead.c
 * @brief     Auto-generated KAT tests for VERUM_ASCON_AEAD128.
 * @details   Known-Answer Tests derived from LWC_AEAD_KAT_128_128.json.
 *            Do not edit manually — regenerate with test/generators/ascon/aead.py.
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

#include <stdint.h>
#include "unity.h"
#include "ascon.h"
#include "verum/ascon/aead.h"

"""

_ENCRYPT_INDENT = ' ' * len('    VERUM_ASCON_AEAD128_encrypt(')
_DECRYPT_INDENT = ' ' * len('    VERUM_ASCON_AEAD128_decrypt(')


def _func_name(pt_len: int, ad_len: int) -> str:
    pt_desc = 'empty' if pt_len == 0 else f'{num_to_words(pt_len)}_byte'
    ad_desc = 'empty' if ad_len == 0 else f'{num_to_words(ad_len)}_byte'
    return f'test_VERUM_ASCON_AEAD128_encrypt_{pt_desc}_pt_{ad_desc}_ad'


def _c_array(qualifier: str, name: str, size: int, data: bytes) -> list[str]:
    q = f'{qualifier} ' if qualifier else ''
    return [
        f'    {q}uint8_t {name}[{size}U] = {{',
        fmt_array_body(data),
        '    };',
    ]


def _call_lines(fn: str, indent: str,
                data_var: str, data_len_str: str,
                has_ad: bool, ad_len: int) -> list[str]:
    pfx = f'    VERUM_ASCON_AEAD128_{fn}('
    lines = [
        f'{pfx}(const uint32_t *) key,',
        f'{indent}(const uint32_t *) nonce,',
        f'{indent}{data_var},',
        f'{indent}{data_len_str},',
    ]
    if has_ad:
        lines += [
            f'{indent}associated_data,',
            f'{indent}{ad_len}U,',
        ]
    lines.append(f'{indent}authentication_tag);')
    return lines


def _generate_test_function(vec: dict, func_name: str) -> str:
    key_bytes   = bytes.fromhex(vec['Key'])
    nonce_bytes = bytes.fromhex(vec['Nonce'])
    pt_bytes    = bytes.fromhex(vec['PT'])  if vec['PT'] else b''
    ad_bytes    = bytes.fromhex(vec['AD'])  if vec['AD'] else b''
    ct_bytes    = bytes.fromhex(vec['CT'])

    pt_len = len(pt_bytes)
    ad_len = len(ad_bytes)

    if len(ct_bytes) < 16:
        raise ValueError(f'CT too short in vector for {func_name}')

    tag_bytes    = ct_bytes[-16:]
    cipher_bytes = ct_bytes[:-16]

    has_pt = pt_len > 0
    has_ad = ad_len > 0

    data_var     = 'plaintext' if has_pt else 'dummy'
    data_len_str = f'{pt_len}U' if has_pt else '0U'

    L: list[str] = []
    L.append(f'static void {func_name}(void)')
    L.append('{')
    L.extend(_c_array('const', 'key',   16, key_bytes))
    L.extend(_c_array('const', 'nonce', 16, nonce_bytes))

    if has_ad:
        L.extend(_c_array('const', 'associated_data', ad_len, ad_bytes))

    if has_pt:
        L.extend(_c_array('const', 'expected_plaintext',  pt_len, pt_bytes))
        L.extend(_c_array('',      'plaintext',            pt_len, pt_bytes))
        L.extend(_c_array('const', 'expected_ciphertext',  pt_len, cipher_bytes))

    L.extend(_c_array('const', 'expected_tag', 16, tag_bytes))

    if not has_pt:
        L.append(f'    uint8_t dummy[1U] = {{ {fmt_byte(0)} }};')

    L.append('    uint32_t authentication_tag[4U] = { 0U };')
    L.append('')
    L.append('    /* --- Encrypt --- */')
    L.extend(_call_lines('encrypt', _ENCRYPT_INDENT, data_var, data_len_str, has_ad, ad_len))

    if has_pt:
        L.append(f'    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, {pt_len}U);')
    L.append('    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t *) authentication_tag, 16U);')
    L.append('')
    L.append('    /* --- Decrypt --- */')
    L.extend(_call_lines('decrypt', _DECRYPT_INDENT, data_var, data_len_str, has_ad, ad_len))

    if has_pt:
        L.append(f'    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_plaintext, plaintext, {pt_len}U);')
    L.append('    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t *) authentication_tag, 16U);')
    L.append('}')
    return '\n'.join(L)


def _generate_runner(entries: list[tuple[str, bool]]) -> str:
    no_ad   = [n for n, had in entries if not had]
    with_ad = [n for n, had in entries if had]
    L = ['int run_aead_tests(void)', '{', '    UNITY_BEGIN();']

    if no_ad:
        L.append('    #ifndef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF')
        for name in no_ad:
            L.append(f'    RUN_TEST({name});')
    if with_ad:
        L.append('    #else')
        for name in with_ad:
            L.append(f'    RUN_TEST({name});')
    if no_ad or with_ad:
        L.append('    #endif')

    L += ['    return UNITY_END();', '}']
    return '\n'.join(L)


def generate(kat_path: Path, out_path: Path) -> None:
    vectors: list[dict] = json.loads(kat_path.read_text(encoding='utf-8'))

    seen: dict[str, int] = {}
    func_names: list[str] = []
    entries: list[tuple[str, bool]] = []

    for vec in vectors:
        pt_len = len(vec['PT']) // 2
        ad_len = len(vec['AD']) // 2
        has_ad = ad_len > 0
        base   = _func_name(pt_len, ad_len)
        count  = seen.get(base, 0) + 1
        seen[base] = count
        fname = base if count == 1 else f'{base}_{count}'
        func_names.append(fname)
        entries.append((fname, has_ad))

    no_ad_blocks:   list[str] = []
    with_ad_blocks: list[str] = []

    for vec, fname in zip(vectors, func_names):
        ad_len = len(vec['AD']) // 2
        try:
            body = _generate_test_function(vec, fname)
        except Exception as exc:
            print(f'WARNING: skipping vector ({fname}): {exc}', file=sys.stderr)
            continue
        (with_ad_blocks if ad_len > 0 else no_ad_blocks).append(body)

    ifdef_lines: list[str] = []
    if no_ad_blocks or with_ad_blocks:
        ifdef_lines.append('#ifndef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF')
        if no_ad_blocks:
            ifdef_lines.append('\n\n'.join(no_ad_blocks))
        if with_ad_blocks:
            ifdef_lines.append('#else /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */')
            ifdef_lines.append('\n\n'.join(with_ad_blocks))
        ifdef_lines.append('#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */')

    blocks: list[str] = [_FILE_HEADER]
    if ifdef_lines:
        blocks.append('\n\n'.join(ifdef_lines))
    blocks.append(_generate_runner(entries))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text('\n\n'.join(blocks) + '\n', encoding='utf-8')
    print(f'[aead]  {len(vectors)} test(s) → {out_path}', file=sys.stderr)


if __name__ == '__main__':
    generate(KAT_AEAD, OUT_AEAD)
