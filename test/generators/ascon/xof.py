#!/usr/bin/env python3

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from _common import (
    KAT_XOF, OUT_XOF,
    fmt_array_body, hex_abbrev, num_to_words,
)

_FILE_HEADER = """\
/**
 * @file      xof.c
 * @brief     Auto-generated KAT tests for VERUM_ASCON_XOF128.
 * @details   Known-Answer Tests derived from LWC_XOF_KAT.json.
 *            Do not edit manually — regenerate with test/generators/ascon/xof.py.
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
#include "verum/ascon/xof.h"

"""


def _func_name(msg_len: int, digest_len: int) -> str:
    msg_part = 'empty_message' if msg_len == 0 else f'{num_to_words(msg_len)}_byte_message'
    out_part = f'{num_to_words(digest_len)}_byte_output'
    return f'test_VERUM_ASCON_XOF128_{msg_part}_{out_part}'


def _generate_test_function(entry: dict) -> str:
    msg_hex    = entry['Msg']
    md_hex     = entry['MD']

    msg_bytes  = bytes.fromhex(msg_hex) if msg_hex else b''
    md_bytes   = bytes.fromhex(md_hex)
    msg_len    = len(msg_bytes)
    digest_len = len(md_bytes)
    abbrev     = hex_abbrev(msg_hex, msg_len)
    name       = _func_name(msg_len, digest_len)

    L: list[str] = []
    L.append(f'static void {name}(void)')
    L.append('{')

    if msg_len == 1:
        L.append(f'    uint8_t  message[1U]   = {{ 0x{msg_bytes[0]:02X}U }};')
    elif msg_len > 1:
        L.append(f'    uint8_t  message[{msg_len}U] = {{')
        L.append(fmt_array_body(msg_bytes))
        L.append('    };')

    L.append(f'    uint8_t  digest[{digest_len}U]  = {{ 0U }};')
    L.append(f'    const uint8_t expected[{digest_len}U] = {{')
    L.append(f'        /* KAT: Ascon-XOF128  Mlen={msg_len}  Dlen={digest_len}  M={abbrev} */')
    L.append(fmt_array_body(md_bytes))
    L.append('    };')
    L.append('')

    if msg_len == 0:
        L.append(f'    VERUM_ASCON_XOF128_digest(NULL, 0U, digest, {digest_len}U);')
    else:
        L.append(f'    VERUM_ASCON_XOF128_digest(message, {msg_len}U, digest, {digest_len}U);')
    L.append('')

    L.append(f'    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, (uint8_t *) digest, {digest_len}U);')
    L.append('}')
    return '\n'.join(L)


def _generate_runner(entries: list[dict]) -> str:
    L = ['int run_xof128_tests(void)', '{', '    UNITY_BEGIN();']
    for e in entries:
        msg_len    = len(bytes.fromhex(e['Msg'])) if e['Msg'] else 0
        digest_len = len(bytes.fromhex(e['MD']))
        L.append(f'    RUN_TEST({_func_name(msg_len, digest_len)});')
    L += ['    return UNITY_END();', '}']
    return '\n'.join(L)


def generate(kat_path: Path, out_path: Path) -> None:
    entries: list[dict] = json.loads(kat_path.read_text(encoding='utf-8'))

    seen: set[tuple[int, int]] = set()
    for i, e in enumerate(entries):
        if 'Msg' not in e or 'MD' not in e:
            sys.exit(f'Entry {i} missing "Msg" or "MD": {e}')
        if not e['MD']:
            sys.exit(f'Entry {i}: MD must not be empty')
        if len(e['MD']) % 2 != 0:
            sys.exit(f'Entry {i}: MD has odd hex char count ({len(e["MD"])})')
        msg_len    = len(bytes.fromhex(e['Msg'])) if e['Msg'] else 0
        digest_len = len(bytes.fromhex(e['MD']))
        key = (msg_len, digest_len)
        if key in seen:
            print(f'Warning: entry {i} duplicates (Mlen={msg_len}, Dlen={digest_len})',
                  file=sys.stderr)
        seen.add(key)

    parts = [_FILE_HEADER]
    for entry in entries:
        parts.append(_generate_test_function(entry))
        parts.append('')
    parts.append(_generate_runner(entries))
    parts.append('')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text('\n'.join(parts), encoding='utf-8')
    print(f'[xof]   {len(entries)} test(s) → {out_path}', file=sys.stderr)


if __name__ == '__main__':
    generate(KAT_XOF, OUT_XOF)
