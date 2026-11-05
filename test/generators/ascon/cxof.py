#!/usr/bin/env python3

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from _common import (
    KAT_CXOF, OUT_CXOF,
    fmt_array_body, hex_abbrev, num_to_words,
)

_FILE_HEADER = """\
/**
 * @file      cxof.c
 * @brief     Auto-generated KAT tests for VERUM_ASCON_CXOF128.
 * @details   Known-Answer Tests derived from LWC_CXOF_KAT.json.
 *            Do not edit manually — regenerate with test/generators/ascon/cxof.py.
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
#include "verum/ascon/cxof.h"

"""


def _func_name(msg_len: int, custom_len: int, digest_len: int) -> str:
    msg_part = 'empty_message' if msg_len == 0 else f'{num_to_words(msg_len)}_byte_message'
    custom_part = 'empty_custom' if custom_len == 0 else f'{num_to_words(custom_len)}_byte_custom'
    out_part = f'{num_to_words(digest_len)}_byte_output'
    return f'test_VERUM_ASCON_CXOF128_{msg_part}_{custom_part}_{out_part}'


def _generate_test_function(entry: dict) -> str:
    msg_hex    = entry['Msg']
    custom_hex = entry.get('Z', entry.get('Custom', ''))
    md_hex     = entry['MD']

    msg_bytes    = bytes.fromhex(msg_hex) if msg_hex else b''
    custom_bytes = bytes.fromhex(custom_hex) if custom_hex else b''
    md_bytes     = bytes.fromhex(md_hex)
    msg_len      = len(msg_bytes)
    custom_len   = len(custom_bytes)
    digest_len   = len(md_bytes)
    msg_abbrev   = hex_abbrev(msg_hex, msg_len)
    cust_abbrev  = hex_abbrev(custom_hex, custom_len)
    name         = _func_name(msg_len, custom_len, digest_len)

    L: list[str] = []
    L.append(f'static void {name}(void)')
    L.append('{')

    if msg_len == 1:
        L.append(f'    uint8_t  message[1U]   = {{ 0x{msg_bytes[0]:02X}U }};')
    elif msg_len > 1:
        L.append(f'    uint8_t  message[{msg_len}U] = {{')
        L.append(fmt_array_body(msg_bytes))
        L.append('    };')

    if custom_len == 1:
        L.append(f'    uint8_t  customization[1U] = {{ 0x{custom_bytes[0]:02X}U }};')
    elif custom_len > 1:
        L.append(f'    uint8_t  customization[{custom_len}U] = {{')
        L.append(fmt_array_body(custom_bytes))
        L.append('    };')

    L.append(f'    uint8_t  digest[{digest_len}U]  = {{ 0U }};')
    L.append(f'    const uint8_t expected[{digest_len}U] = {{')
    L.append(f'        /* KAT: Ascon-CXOF128  Mlen={msg_len}  Zlen={custom_len}  Dlen={digest_len}  M={msg_abbrev}  Z={cust_abbrev} */')
    L.append(fmt_array_body(md_bytes))
    L.append('    };')
    L.append('')

    msg_arg = 'NULL' if msg_len == 0 else 'message'
    custom_arg = 'NULL' if custom_len == 0 else 'customization'

    L.append(f'    VERUM_ASCON_CXOF128_digest({msg_arg}, {msg_len}U, {custom_arg}, {custom_len}U, digest, {digest_len}U);')
    L.append('')
    L.append(f'    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, (uint8_t *) digest, {digest_len}U);')
    L.append('}')
    return '\n'.join(L)


def _generate_runner(entries: list[dict]) -> str:
    L = ['int run_cxof128_tests(void)', '{', '    UNITY_BEGIN();']
    for e in entries:
        msg_len    = len(bytes.fromhex(e['Msg'])) if e['Msg'] else 0
        custom_len = len(bytes.fromhex(e.get('Z', e.get('Custom', '')))) if e.get('Z', e.get('Custom', '')) else 0
        digest_len = len(bytes.fromhex(e['MD']))
        L.append(f'    RUN_TEST({_func_name(msg_len, custom_len, digest_len)});')
    L += ['    return UNITY_END();', '}']
    return '\n'.join(L)


def generate(kat_path: Path, out_path: Path) -> None:
    entries: list[dict] = json.loads(kat_path.read_text(encoding='utf-8'))

    seen: set[tuple[int, int, int]] = set()
    for i, e in enumerate(entries):
        if 'Msg' not in e or 'MD' not in e:
            sys.exit(f'Entry {i} missing "Msg" or "MD": {e}')
        if not e['MD']:
            sys.exit(f'Entry {i}: MD must not be empty')
        if len(e['MD']) % 2 != 0:
            sys.exit(f'Entry {i}: MD has odd hex char count ({len(e["MD"])})')
        msg_len    = len(bytes.fromhex(e['Msg'])) if e['Msg'] else 0
        custom_len = len(bytes.fromhex(e.get('Z', e.get('Custom', '')))) if e.get('Z', e.get('Custom', '')) else 0
        digest_len = len(bytes.fromhex(e['MD']))
        key = (msg_len, custom_len, digest_len)
        if key in seen:
            print(f'Warning: entry {i} duplicates (Mlen={msg_len}, Zlen={custom_len}, Dlen={digest_len})',
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
    print(f'[cxof]  {len(entries)} test(s) → {out_path}', file=sys.stderr)


if __name__ == '__main__':
    generate(KAT_CXOF, OUT_CXOF)
