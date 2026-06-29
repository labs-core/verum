from pathlib import Path

_GENERATORS_DIR = Path(__file__).parent
_TEST_DIR       = _GENERATORS_DIR.parent
_SUITE_DIR      = _TEST_DIR / 'suite'
_KAT_DIR        = _GENERATORS_DIR / 'kat'

KAT_AEAD = _KAT_DIR / 'LWC_AEAD_KAT_128_128.json'
KAT_HASH = _KAT_DIR / 'LWC_HASH_KAT_256.json'
KAT_XOF  = _KAT_DIR / 'LWC_XOF_KAT.json'

OUT_AEAD = _SUITE_DIR / 'ascon' / 'aead.c'
OUT_HASH = _SUITE_DIR / 'ascon' / 'hash.c'
OUT_XOF  = _SUITE_DIR / 'ascon' / 'xof.c'

_ONES = [
    '', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight',
    'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen',
    'sixteen', 'seventeen', 'eighteen', 'nineteen',
]
_TENS = [
    '', '', 'twenty', 'thirty', 'forty', 'fifty',
    'sixty', 'seventy', 'eighty', 'ninety',
]


def num_to_words(n: int) -> str:
    if n < 0:
        raise ValueError('num_to_words: negative input')
    if n < 20:
        return _ONES[n]
    if n < 100:
        return _TENS[n // 10] + _ONES[n % 10]
    if n < 1000:
        rest = n % 100
        return _ONES[n // 100] + 'hundred' + (num_to_words(rest) if rest else '')
    return str(n)


def fmt_byte(b: int) -> str:
    return f'0x{b:02X}U'


def fmt_array_body(data: bytes, indent: str = '        ') -> str:
    rows = []
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        rows.append(indent + ', '.join(fmt_byte(b) for b in chunk))
    return ',\n'.join(rows)


def hex_abbrev(hex_str: str, byte_len: int) -> str:
    if byte_len == 0:
        return '(empty)'
    if len(hex_str) <= 20:
        return hex_str.upper()
    return hex_str[:6].upper() + '...' + hex_str[-4:].upper()
