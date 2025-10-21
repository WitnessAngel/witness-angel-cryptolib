from typing import Tuple

import pyasn1.codec.der.encoder
import pyasn1.type.univ
import base64
import rsa_ as rsa


base64.encodestring = lambda x: base64.b64encode(x)


def private_key_pem(n: int, e: int, d: int, p: int, q: int, dP: int, dQ: int, qInv: int) -> str:
    '''Create a private key PEM file
    https://0day.work/how-i-recovered-your-private-key-or-why-small-keys-are-bad/'''
    template = '-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n'
    seq = pyasn1.type.univ.Sequence()
    for x in [0, n, e, d, p, q, dP, dQ, qInv]:
        seq.setComponentByPosition(len(seq), pyasn1.type.univ.Integer(x))
    der = pyasn1.codec.der.encoder.encode(seq)
    return template.format(base64.encodestring(der).decode('ascii'))


def public_key_pem(n: int, e: int) -> str:
    '''Create a public key PEM file'''
    template = '-----BEGIN RSA PUBLIC KEY-----\n{}-----END RSA PUBLIC KEY-----\n'
    seq = pyasn1.type.univ.Sequence()
    for x in [n, e]:
        seq.setComponentByPosition(len(seq), pyasn1.type.univ.Integer(x))
    der = pyasn1.codec.der.encoder.encode(seq)
    return template.format(base64.encodestring(der).decode('ascii'))


def create_key_pair(p: int, q: int, e: int = None) -> Tuple[str, str]:
    pub, prv = rsa.keygen(p, q, e)
    e, n = pub
    d, _ = prv
    dP = rsa.modinv(e, p - 1)
    dQ = rsa.modinv(e, q - 1)
    qInv = rsa.modinv(q, p)
    pub_pem = public_key_pem(n, e)
    prv_pem = private_key_pem(n, e, d, p, q, dP, dQ, qInv)
    return pub_pem, prv_pem
