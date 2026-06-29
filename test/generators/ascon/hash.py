#!/usr/bin/env python3

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from _common import (
    KAT_HASH, OUT_HASH,
    fmt_array_body, hex_abbrev, num_to_words,
)

_DIGEST_BYTES = 32

_FILE_HEADER = """\
/**
 * @file      hash.c
 * @brief     Auto-generated KAT tests for VERUM_ASCON_HASH256.
 * @details   Known-Answer Tests derived from LWC_HASH_KAT_256.json.
 *            Do not edit manually — regenerate with test/generators/ascon/hash.py.
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
#include "verum/ascon/hash.h"

"""


def _func_name(msg_len: int) -> str:
    suffix = 'empty_message' if msg_len == 0 else f'{num_to_words(msg_len)}_byte_message'
    return f'test_VERUM_ASCON_HASH256_{suffix}'


def _generate_test_function(entry: dict) -> str:
    msg_hex = entry['Msg']
    md_hex  = entry['MD']

    msg_bytes = bytes.fromhex(msg_hex) if msg_hex else b''
    md_bytes  = bytes.fromhex(md_hex)
    msg_len   = len(msg_bytes)
    abbrev    = hex_abbrev(msg_hex, msg_len)
    name      = _func_name(msg_len)

    L: list[str] = []
    L.append(f'static void {name}(void)')
    L.append('{')

    if msg_len == 1:
        L.append(f'    uint8_t  message[1U]         = {{ 0x{msg_bytes[0]:02X}U }};')
    elif msg_len > 1:
        L.append(f'    uint8_t  message[{msg_len}U] = {{')
        L.append(fmt_array_body(msg_bytes))
        L.append('    };')

    L.append('    uint32_t digest[8U]          = { 0U };')
    L.append(f'    const uint8_t expected[{_DIGEST_BYTES}U]  = {{')
    L.append(f'        /* KAT: Ascon-Hash256  Mlen={msg_len}  M={abbrev} */')
    L.append(fmt_array_body(md_bytes))
    L.append('    };')
    L.append('')

    if msg_len == 0:
        L.append('    VERUM_ASCON_HASH256_digest(NULL, 0U, digest);')
    else:
        L.append(f'    VERUM_ASCON_HASH256_digest(message, {msg_len}U, digest);')
    L.append('')

    L.append(f'    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, (uint8_t *) digest, {_DIGEST_BYTES}U);')
    L.append('}')
    return '\n'.join(L)


def _generate_runner(entries: list[dict]) -> str:
    L = ['int run_hash256_tests(void)', '{', '    UNITY_BEGIN();']
    for e in entries:
        msg_len = len(bytes.fromhex(e['Msg'])) if e['Msg'] else 0
        L.append(f'    RUN_TEST({_func_name(msg_len)});')
    L += ['    return UNITY_END();', '}']
    return '\n'.join(L)


def generate(kat_path: Path, out_path: Path) -> None:
    entries: list[dict] = json.loads(kat_path.read_text(encoding='utf-8'))

    for i, e in enumerate(entries):
        if 'Msg' not in e or 'MD' not in e:
            sys.exit(f'Entry {i} missing "Msg" or "MD": {e}')
        if len(e['MD']) != 64:
            sys.exit(f'Entry {i}: MD must be 64 hex chars, got {len(e["MD"])}')

    parts = [_FILE_HEADER]
    for entry in entries:
        parts.append(_generate_test_function(entry))
        parts.append('')
    parts.append(_generate_runner(entries))
    parts.append('')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text('\n'.join(parts), encoding='utf-8')
    print(f'[hash]  {len(entries)} test(s) → {out_path}', file=sys.stderr)


if __name__ == '__main__':
    generate(KAT_HASH, OUT_HASH)
