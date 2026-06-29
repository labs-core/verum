#!/usr/bin/env python3

import argparse
import importlib
import sys
from pathlib import Path

_GENERATORS_DIR = Path(__file__).parent
_TEST_DIR       = _GENERATORS_DIR.parent
_RUNNER_PATH    = _TEST_DIR / 'runner.c'

sys.path.insert(0, str(_GENERATORS_DIR))

FAMILIES: dict[str, list[tuple[str, str, str, str]]] = {
    'ascon': [
        ('aead', 'ascon.aead', 'ASCON AEAD-128',  'run_aead_tests'),
        ('hash', 'ascon.hash', 'ASCON Hash-256',  'run_hash256_tests'),
        ('xof',  'ascon.xof',  'ASCON XOF-128',   'run_xof128_tests'),
    ],
}

_RUNNER_HEADER = """\
/**
 * @file      runner.c
 * @brief     Auto-generated test runner.
 * @details   Do not edit manually — regenerate with test/generators/all.py.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */

#include "unity.h"
#include <stdio.h>
#include <string.h>
"""

_RUNNER_PUTCHAR = """
#define LINE_BUF_SIZE 1024
static char s_buf[LINE_BUF_SIZE];
static int  s_pos = 0;

void runner_putchar(int c)
{
    if (c == '\\n')
    {
        s_buf[s_pos] = '\\0';
        int print_it =
            (strstr(s_buf, ":FAIL")   != NULL) ||
            (strstr(s_buf, ":IGNORE") != NULL) ||
            (strstr(s_buf, " Tests ") != NULL) ||
            (strcmp(s_buf, "OK")   == 0)       ||
            (strcmp(s_buf, "FAIL") == 0);
        if (print_it)
        {
            puts(s_buf);
            fflush(stdout);
        }
        s_pos = 0;
    }
    else
    {
        if (s_pos < LINE_BUF_SIZE - 1)
        {
            s_buf[s_pos++] = (char) c;
        }
    }
}

static int run_suite(const char *name, int (*suite)(void))
{
    printf("\\n=== %-40s ===\\n", name);
    fflush(stdout);
    int result = suite();
    printf("=== %-40s ===\\n", result == 0 ? "PASSED" : "FAILED");
    fflush(stdout);
    return result;
}

void setUp(void)
{
}

void tearDown(void)
{
}
"""


def _generate_runner(active: list[tuple[str, str, str, str]]) -> str:
    includes = []
    seen_families: list[str] = []
    for name, module_path, _label, _fn in active:
        family = module_path.split('.')[0]
        if family not in seen_families:
            seen_families.append(family)
            includes.append(f'#include "./suite/{family}/{family}.h"')

    forward_decls = [
        f'int {fn}(void);'
        for _name, _mod, _label, fn in active
    ]

    suite_calls = [
        f'    failures += run_suite("{label}", {fn});'
        for _name, _mod, label, fn in active
    ]

    lines = [
        _RUNNER_HEADER.rstrip(),
        '\n'.join(includes),
        _RUNNER_PUTCHAR.rstrip(),
        '',
        '\n'.join(forward_decls),
        '',
        'int main(void)',
        '{',
        '    int failures = 0;',
        '',
    ]
    lines.extend(suite_calls)
    lines += [
        '',
        '    printf("\\n%s: %d\\n", failures == 0 ? "ALL SUITES PASSED" : "SOME SUITES FAILED", failures);',
        '    return failures;',
        '}',
        '',
    ]
    return '\n'.join(lines)


def _load(module_path: str):
    sys.path.insert(0, str(_GENERATORS_DIR / module_path.split('.')[0]))
    return importlib.import_module(module_path)


def _run(family: str, targets: list[str]) -> tuple[bool, list[tuple[str, str, str, str]]]:
    if family not in FAMILIES:
        print(f'ERROR: unknown family "{family}". '
              f'Available: {", ".join(FAMILIES)}', file=sys.stderr)
        return False, []

    descriptors = FAMILIES[family]
    if targets:
        unknown = set(targets) - {name for name, *_ in descriptors}
        if unknown:
            print(f'ERROR: unknown target(s) for {family}: '
                  f'{", ".join(sorted(unknown))}', file=sys.stderr)
            return False, []
        descriptors = [d for d in descriptors if d[0] in targets]

    ok = True
    generated: list[tuple[str, str, str, str]] = []
    for name, module_path, label, runner_fn in descriptors:
        try:
            mod = _load(module_path)
            kat_attr = f'KAT_{name.upper()}'
            out_attr = f'OUT_{name.upper()}'
            mod.generate(getattr(mod, kat_attr), getattr(mod, out_attr))
            generated.append((name, module_path, label, runner_fn))
        except Exception as exc:
            print(f'ERROR [{family}:{name}]: {exc}', file=sys.stderr)
            ok = False
    return ok, generated


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Generate KAT test files and runner.c for all supported cipher families.')
    parser.add_argument(
        'targets', nargs='*',
        metavar='FAMILY[:TARGET,...]',
        help=(
            'Targets to generate. '
            'Examples: ascon  ascon:xof  ascon:aead,hash  '
            '(default: all families, all targets)'
        ),
    )
    args = parser.parse_args()

    plan: dict[str, list[str]] = {}
    if not args.targets:
        plan = {f: [] for f in FAMILIES}
    else:
        for token in args.targets:
            if ':' in token:
                family, rest = token.split(':', 1)
                plan.setdefault(family, []).extend(rest.split(','))
            else:
                plan.setdefault(token, [])

    ok = True
    all_generated: list[tuple[str, str, str, str]] = []

    for family, targets in plan.items():
        success, generated = _run(family, targets)
        if not success:
            ok = False
        all_generated.extend(generated)

    if all_generated:
        runner_src = _generate_runner(all_generated)
        _RUNNER_PATH.write_text(runner_src, encoding='utf-8')
        print(f'[runner] → {_RUNNER_PATH}', file=sys.stderr)

    if ok:
        print('Done.', file=sys.stderr)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
