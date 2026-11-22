# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Check that text strings are sequences of Unicode scalar values, as the cryptainer formats require.

A MicroPython str holds raw UTF-8 bytes, only checked for their structure: chr(0xD800), b"\\xed\\xa0\\x80".decode()
(an encoded surrogate), b"\\xc0\\x80".decode() (an overlong form) or str(b"\\xf4\\x90\\x80\\x80", "utf8") (above
U+10FFFF) are accepted, and its json module writes them as is. wacryptolib then can't load the cryptainer, nor decode
the key structs which hold the metadata inside every asymmetric ciphertext, so the payload is lost. The bytes given by
str.encode() are therefore validated strictly, which doesn't depend on how the interpreter stores strings (CPython
refuses to encode lone surrogates). This is cheap: ASCII strings are recognized by max(), in native code.
"""


def is_well_formed_utf8(data) -> bool:
    """Tell whether these bytes are well-formed UTF-8 (table 3-7 of the Unicode standard): no overlong form, no
    encoded surrogate (U+D800..U+DFFF), nothing above U+10FFFF, no truncated or stray continuation byte."""
    if not data or max(data) < 0x80:  # ASCII
        return True
    length = len(data)
    i = 0
    while i < length:
        lead = data[i]
        if lead < 0x80:
            i += 1
            continue
        # Count of continuation bytes, and allowed range of the first of them
        if 0xC2 <= lead <= 0xDF:
            count, low, high = 1, 0x80, 0xBF
        elif lead == 0xE0:
            count, low, high = 2, 0xA0, 0xBF  # Not overlong
        elif lead == 0xED:
            count, low, high = 2, 0x80, 0x9F  # Not a surrogate
        elif 0xE1 <= lead <= 0xEF:
            count, low, high = 2, 0x80, 0xBF
        elif lead == 0xF0:
            count, low, high = 3, 0x90, 0xBF  # Not overlong
        elif 0xF1 <= lead <= 0xF3:
            count, low, high = 3, 0x80, 0xBF
        elif lead == 0xF4:
            count, low, high = 3, 0x80, 0x8F  # Not above U+10FFFF
        else:  # Continuation byte, overlong lead byte 0xC0 or 0xC1, or 0xF5..0xFF
            return False
        end = i + 1 + count
        if end > length or not low <= data[i + 1] <= high:
            return False
        for j in range(i + 2, end):
            if not 0x80 <= data[j] <= 0xBF:
                return False
        i = end
    return True


def is_well_formed_text(text: str) -> bool:
    """Tell whether this str is a sequence of Unicode scalar values (so without lone surrogates)."""
    try:
        data = text.encode()
    except UnicodeError:  # CPython can't encode lone surrogates in UTF-8
        return False
    return is_well_formed_utf8(data)


def find_ill_formed_text(tree):
    """Look for a str which is not a sequence of Unicode scalar values in a data tree, dict keys included, at any
    depth of its dicts, lists and tuples.

    :return: None if there is none, else the location of the first one found, relative to the tree: e.g. "" for
        the tree itself, '["a"][2]' for a value, '["a"] (a key)' for a key of the dict at '["a"]'
    """
    if isinstance(tree, str):
        return None if is_well_formed_text(tree) else ""
    if isinstance(tree, dict):
        for key in tree:
            if isinstance(key, str) and not is_well_formed_text(key):
                return " (a key)"  # The key itself is not shown, it may be unprintable
        items = tree.items()
    elif isinstance(tree, (list, tuple)):
        items = enumerate(tree)
    else:  # Bytes, numbers, UUIDs... hold no text
        return None
    for key, value in items:
        location = find_ill_formed_text(value)
        if location is not None:
            return "[%r]%s" % (key, location)
    return None


def get_ill_formed_text_message(label: str, location: str) -> str:
    """Error message for a location returned by find_ill_formed_text() in the tree named label."""
    return (
        "Text string of %s%s is not a sequence of Unicode scalar values (lone surrogate, overlong form or invalid "
        "UTF-8), which cryptainers can't hold" % (label, location)
    )
