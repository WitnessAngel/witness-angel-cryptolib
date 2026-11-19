import os
import binascii

_bytes, _int = bytes, int  # Shadowed by the arguments and properties of UUID, like in CPython


class UUID:
    """Minimal UUID value, comparable and hashable like CPython's one (so usable as a dict key)."""

    def __init__(self, hex=None, bytes=None, bytes_le=None, fields=None, int=None, version=None):
        assert bytes_le is None and fields is None and version is None  # Micropython limitation
        if [hex, bytes, int].count(None) != 2:
            raise TypeError('one of the hex, bytes or int arguments must be given')
        if hex is not None:
            hex = hex.replace('urn:', '').replace('uuid:', '').strip('{}').replace('-', '')
            if len(hex) != 32:
                raise ValueError('badly formed hexadecimal UUID string')
            bytes = binascii.unhexlify(hex)
        elif int is not None:
            if not 0 <= int < 1 << 128:
                raise ValueError('int is out of range (need a 128-bit value)')
            bytes = int.to_bytes(16, 'big')
        if len(bytes) != 16:
            raise ValueError('bytes arg must be 16 bytes long')
        self._bytes = _bytes(bytes)  # Immutable copy, since it is hashed

    @property
    def bytes(self):
        return self._bytes

    @property
    def int(self):
        return _int.from_bytes(self._bytes, 'big')

    @property
    def hex(self):
        return binascii.hexlify(self._bytes).decode()

    def __eq__(self, other):
        return isinstance(other, UUID) and self._bytes == other._bytes

    def __hash__(self):
        return hash(self._bytes)

    def __str__(self):
        h = self.hex
        return '-'.join((h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]))

    def __repr__(self):
        return "<UUID: %s>" % str(self)


def uuid4():
    """Generates a random UUID compliant to RFC 4122 pg.14"""
    random = bytearray(os.urandom(16))
    random[6] = (random[6] & 0x0F) | 0x40
    random[8] = (random[8] & 0x3F) | 0x80
    return UUID(bytes=random)
