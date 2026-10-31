# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Minimal and strict DER codec, and the few PEM structures that wacryptolib reads and writes, byte-compatible with
the pycryptodome backend: PKCS#1 RSA private keys, PKCS#8 private keys, SubjectPublicKeyInfo public keys,
and PBES2 (PBKDF2 + AES-CBC) encrypted PKCS#8 private keys.

Every parsing failure raises ValueError, since PEM data may come from untrusted sources.
"""

import base64
import binascii
import hashlib

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30

OID_RSA = "1.2.840.113549.1.1.1"
OID_DSA = "1.2.840.10040.4.1"
OID_X25519 = "1.3.101.110"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"  # NIST curves

OID_PBES2 = "1.2.840.113549.1.5.13"
OID_PBKDF2 = "1.2.840.113549.1.5.12"
OID_HMAC_SHA1 = "1.2.840.113549.2.7"
OID_HMAC_SHA256 = "1.2.840.113549.2.9"
AES_CBC_OIDS_TO_KEY_LENGTH = {
    "2.16.840.1.101.3.4.1.2": 16,
    "2.16.840.1.101.3.4.1.22": 24,
    "2.16.840.1.101.3.4.1.42": 32,
}
OID_AES256_CBC = "2.16.840.1.101.3.4.1.42"

# Same values as in the pycryptodome backend
PEM_PBKDF2_ITERATIONS = 600000
PEM_PBKDF2_MAX_ITERATIONS = 10_000_000
PEM_DECRYPTION_ERROR = "Wrong passphrase or corrupted encrypted private key"


def _malformed():
    return ValueError("Malformed DER structure")


# DER ENCODING #


def _encode_tlv(tag, value):
    length = len(value)
    if length < 0x80:
        header = bytes([length])
    else:
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(length_bytes)]) + length_bytes
    return bytes([tag]) + header + value


def encode_integer(value):
    assert value >= 0, "Negative DER integer"
    return _encode_tlv(TAG_INTEGER, value.to_bytes(value.bit_length() // 8 + 1, "big"))  # Minimal, with sign bit 0


def encode_octet_string(value):
    return _encode_tlv(TAG_OCTET_STRING, value)


def encode_bit_string(value):
    return _encode_tlv(TAG_BIT_STRING, b"\x00" + value)  # No unused bits


def encode_null():
    return _encode_tlv(TAG_NULL, b"")


def encode_oid(dotted_oid):
    arcs = [int(arc) for arc in dotted_oid.split(".")]
    body = b""
    for arc in [arcs[0] * 40 + arcs[1]] + arcs[2:]:
        chunk = [arc & 0x7F]
        while arc > 0x7F:
            arc >>= 7
            chunk.insert(0, 0x80 | (arc & 0x7F))
        body += bytes(chunk)
    return _encode_tlv(TAG_OID, body)


def encode_sequence(*encoded_items):
    return _encode_tlv(TAG_SEQUENCE, b"".join(encoded_items))


# DER DECODING #


def _read_tlv(data, position):
    """Return (tag, value, next_position), only accepting minimal definite lengths."""
    if position + 2 > len(data):
        raise _malformed()
    tag, length = data[position], data[position + 1]
    position += 2
    if length & 0x80:
        length_byte_count = length & 0x7F
        if not 1 <= length_byte_count <= 4 or position + length_byte_count > len(data):
            raise _malformed()  # Indefinite or absurd length
        length_bytes = data[position : position + length_byte_count]
        length = int.from_bytes(length_bytes, "big")
        if length < 0x80 or length_bytes[0] == 0:
            raise _malformed()  # Non-minimal length encoding
        position += length_byte_count
    end = position + length
    if end > len(data):
        raise _malformed()
    return tag, data[position:end], end


def decode(data, expected_tag):
    """Return the value of the single DER element making up `data`."""
    tag, value, end = _read_tlv(data, 0)
    if tag != expected_tag or end != len(data):
        raise _malformed()
    return value


def decode_sequence(data, min_items, max_items=None):
    """Return the list of encoded items of the DER sequence making up `data`."""
    content = decode(data, TAG_SEQUENCE)
    items = []
    position = 0
    while position < len(content):
        _tag, _value, next_position = _read_tlv(content, position)
        items.append(content[position:next_position])
        position = next_position
    if not min_items <= len(items) <= (max_items if max_items is not None else min_items):
        raise _malformed()
    return items


def decode_integer(data):
    value = decode(data, TAG_INTEGER)
    if not value or value[0] & 0x80 or (len(value) > 1 and value[0] == 0 and not value[1] & 0x80):
        raise _malformed()  # Empty, negative or non-minimal
    return int.from_bytes(value, "big")


def decode_octet_string(data):
    return decode(data, TAG_OCTET_STRING)


def decode_bit_string(data):
    value = decode(data, TAG_BIT_STRING)
    if not value or value[0] != 0:
        raise _malformed()  # Only whole bytes are used here
    return value[1:]


def decode_null(data):
    if decode(data, TAG_NULL) != b"":
        raise _malformed()


def decode_oid(data):
    value = decode(data, TAG_OID)
    if not value or value[-1] & 0x80:
        raise _malformed()
    arcs = []
    arc = 0
    for index, byte in enumerate(value):
        if arc == 0 and byte == 0x80:
            raise _malformed()  # Non-minimal arc
        arc = (arc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(arc)
            arc = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first] + arcs[1:])


# PEM ARMOR #


def encode_pem(der, marker):
    """Same layout as pycryptodome's PEM.encode(): 64-characters lines, no trailing newline."""
    lines = [binascii.b2a_base64(der[i : i + 48]).decode("ascii") for i in range(0, len(der), 48)]
    return ("-----BEGIN %s-----\n%s-----END %s-----" % (marker, "".join(lines), marker)).encode("ascii")


def decode_pem(key_pem):
    """Return (der, marker); encapsulated headers (legacy OpenSSL encryption) are rejected."""
    if isinstance(key_pem, bytes):
        try:
            key_pem = key_pem.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("PEM data must be ASCII") from None
    lines = [line.strip() for line in key_pem.strip().splitlines()]  # Like pycryptodome, ignore stray spaces
    if len(lines) < 2 or not lines[0].startswith("-----BEGIN ") or not lines[0].endswith("-----"):
        raise ValueError("Not a PEM-encoded key")
    marker = lines[0][len("-----BEGIN ") : -len("-----")]
    if lines[-1] != "-----END %s-----" % marker:
        raise ValueError("Missing PEM end marker for %s" % marker)
    body = ["".join(line.split()) for line in lines[1:-1]]
    if any(":" in line for line in body):
        raise ValueError("PEM encapsulated headers (legacy encryption) are not supported by the fallback backend")
    try:
        der = base64.b64decode("".join(body), validate=True)
    except binascii.Error:
        raise ValueError("Invalid base64 data in PEM") from None
    return der, marker


# PKCS#8 AND SUBJECT PUBLIC KEY INFO #


def encode_algorithm_identifier(oid, parameters=None):
    return encode_sequence(encode_oid(oid), *([parameters] if parameters is not None else []))


def decode_algorithm_identifier(data):
    """Return (oid, encoded parameters or None)."""
    items = decode_sequence(data, 1, 2)
    return decode_oid(items[0]), (items[1] if len(items) == 2 else None)


def encode_pkcs8(algorithm_identifier, private_key_octets):
    return encode_sequence(encode_integer(0), algorithm_identifier, encode_octet_string(private_key_octets))


def decode_pkcs8(der):
    """Return (oid, encoded parameters or None, private key octets); like pycryptodome, the optional attributes
    and (for PKCS#8 v2, i.e. OneAsymmetricKey) public key are ignored."""
    version, algorithm_identifier, private_key, *optional_items = decode_sequence(der, 3, 5)
    if len(optional_items) > {0: 1, 1: 2}.get(decode_integer(version), -1):
        raise ValueError("Unsupported PKCS#8 version")
    oid, parameters = decode_algorithm_identifier(algorithm_identifier)
    return oid, parameters, decode_octet_string(private_key)


def encode_spki(algorithm_identifier, public_key_bits):
    return encode_sequence(algorithm_identifier, encode_bit_string(public_key_bits))


def decode_spki(der):
    """Return (oid, encoded parameters or None, public key bits)."""
    algorithm_identifier, public_key = decode_sequence(der, 2)
    oid, parameters = decode_algorithm_identifier(algorithm_identifier)
    return oid, parameters, decode_bit_string(public_key)


# PBES2 ENCRYPTION OF PKCS#8 #


def encrypt_pkcs8_to_pem(clear_pkcs8_der, passphrase, encrypt_via_aes_cbc, random_bytes):
    """PBES2 with PBKDF2-HMAC-SHA256 and AES256-CBC, exactly like the pycryptodome backend."""
    salt, iv = random_bytes(16), random_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", passphrase, salt, PEM_PBKDF2_ITERATIONS, dklen=32)
    ciphertext = encrypt_via_aes_cbc(clear_pkcs8_der, key=key, iv=iv)
    pbkdf2_parameters = encode_sequence(
        encode_octet_string(salt),
        encode_integer(PEM_PBKDF2_ITERATIONS),
        encode_algorithm_identifier(OID_HMAC_SHA256, encode_null()),
    )
    pbes2_parameters = encode_sequence(
        encode_algorithm_identifier(OID_PBKDF2, pbkdf2_parameters),
        encode_algorithm_identifier(OID_AES256_CBC, encode_octet_string(iv)),
    )
    encrypted_der = encode_sequence(
        encode_algorithm_identifier(OID_PBES2, pbes2_parameters), encode_octet_string(ciphertext)
    )
    return encode_pem(encrypted_der, "ENCRYPTED PRIVATE KEY")


def decrypt_pkcs8(encrypted_der, passphrase, decrypt_via_aes_cbc):
    """Return the clear PKCS#8 DER; accepts PBKDF2 with HMAC-SHA1 (also when implicit) or HMAC-SHA256,
    and AES-CBC, i.e. what this library wrote with any of its versions (except DES3-protected keys: DSA ones
    until 0.12, RSA ones until 0.8)."""
    algorithm_identifier, ciphertext = decode_sequence(encrypted_der, 2)
    pbes2_oid, pbes2_parameters = decode_algorithm_identifier(algorithm_identifier)
    if pbes2_oid != OID_PBES2 or pbes2_parameters is None:
        raise ValueError("Unsupported private key protection (only PBES2 is supported by the fallback backend)")
    kdf, cipher = decode_sequence(pbes2_parameters, 2)
    kdf_oid, kdf_parameters = decode_algorithm_identifier(kdf)
    cipher_oid, iv = decode_algorithm_identifier(cipher)
    if kdf_oid != OID_PBKDF2 or kdf_parameters is None or cipher_oid not in AES_CBC_OIDS_TO_KEY_LENGTH or iv is None:
        raise ValueError("Unsupported private key protection (only PBKDF2 and AES-CBC are supported)")
    key_length = AES_CBC_OIDS_TO_KEY_LENGTH[cipher_oid]

    salt, iteration_count, *optional_items = decode_sequence(kdf_parameters, 2, 4)
    salt, iteration_count, iv = decode_octet_string(salt), decode_integer(iteration_count), decode_octet_string(iv)
    hash_name = "sha1"
    # PBKDF2-params order (RFC 8018): at most one keyLength INTEGER, then at most one prf AlgorithmIdentifier
    if [item[0] == TAG_INTEGER for item in optional_items] not in ([], [True], [False], [True, False]):
        raise ValueError("Malformed encrypted private key")
    for item in optional_items:
        if item[0] == TAG_INTEGER:
            if decode_integer(item) != key_length:
                raise ValueError("Malformed encrypted private key")
        else:
            prf_oid, prf_parameters = decode_algorithm_identifier(item)
            if prf_parameters is not None:
                decode_null(prf_parameters)
            hash_name = {OID_HMAC_SHA1: "sha1", OID_HMAC_SHA256: "sha256"}.get(prf_oid)
            if hash_name is None:
                raise ValueError("Unsupported PBKDF2 pseudo-random function")

    if not 0 < iteration_count <= PEM_PBKDF2_MAX_ITERATIONS:
        raise ValueError("Unsupported PBKDF2 iteration count in encrypted private key")
    ciphertext = decode_octet_string(ciphertext)
    if len(iv) != 16 or not ciphertext or len(ciphertext) % 16:
        raise ValueError("Malformed encrypted private key")

    key = hashlib.pbkdf2_hmac(hash_name, passphrase, salt, iteration_count, dklen=key_length)
    try:
        return decrypt_via_aes_cbc(ciphertext, key=key, iv=iv)
    except ValueError:  # Bad padding
        raise ValueError(PEM_DECRYPTION_ERROR) from None
