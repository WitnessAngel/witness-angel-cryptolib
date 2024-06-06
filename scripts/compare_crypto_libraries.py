import sys
from wolfcrypt.hashes import Sha256
from wolfcrypt.asn import pem_to_der, der_to_pem
from wolfcrypt.ciphers import Aes, MODE_CBC, RsaPublic, HASH_TYPE_SHA, RsaPrivate, HASH_TYPE_SHA512

from wacryptolib._crypto_backend import pad_bytes, AES_BLOCK_SIZE, get_random_bytes
from wacryptolib.cipher import encrypt_bytestring, decrypt_bytestring, _encrypt_via_rsa_oaep, _decrypt_via_rsa_oaep
from wacryptolib.keygen import generate_symkey, load_asymmetric_key_from_pem_bytestring
from wolfcrypt._ffi import lib as _lib

plaintext = b"Every"  # get_random_bytes(500)
print(">>>>>>> plaintext", plaintext)

## der = pem_to_der(_lib.publi)
"""
from binascii import hexlify as b2h, unhexlify as h2b

public_key_der = h2b(
    "30819F300D06092A864886F70D010101050003818D0030818902818100BC"
    "730EA849F374A2A9EF18A5DA559921F9C8ECB36D48E53535757737ECD161"
    "905F3ED9E4D5DF94CAC1A9D719DA86C9E84DC4613682FEABAD7E7725BB8D"
    "11A5BC623AA838CC39A20466B4F7F7F3AADA4D020EBB5E8D6948DC77C928"
    "0E22E96BA426BA4CE8C1FD4A6F2B1FEF8AAEF69062E5641EEB2B3C67C8DC"
    "2700F6916865A90203010001"
)

pem = der_to_pem(public_key_der, _lib.PUBLICKEY_TYPE)
print("RSA PUBLIC PEM", pem)

cipher = RsaPublic(public_key_der, hash_type=HASH_TYPE_SHA)


##cipher = RsaPublic.from_pem(public_key_pem)'''

print("RSA CIPHER", cipher)

res = cipher.encrypt_oaep(plaintext)
print("RSA CIPHERTEXT RESULT", res)
"""

pem_public = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5r9AL45wYSm4//EBVSCL
0VgTMJ8cNLDeWAO4XsgbhbyYDUJOrnzn/ntQLfUKfR9UPwyWbIpwOmpnzVizOlhe
PbtpsbbWK7Yg+7xOlWQicMW7LUZSmEAEbzqC22HQEJ5g3npq6kx3oOyCpqmXq9VZ
q9xKqpDrqSR1N2r/Pr9qxDagC/f9efIJ1mQkmjYax/dGsYf69vVq6kP2S2+mQYTB
KOr3YU4uZ5olVkr4jiwstdMEKiUdki5aw2eByk6Q8x0geTakLtV4xw3KdF959QXM
plMoOCAhOdeDiSFfQXqTV/nq1I/ox0xeZPfYrbQAbFQ1ld6thkzQj720G2jTlmWB
cQIDAQAB
-----END PUBLIC KEY-----"""

pem_private = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA5r9AL45wYSm4//EBVSCL0VgTMJ8cNLDeWAO4XsgbhbyYDUJO
rnzn/ntQLfUKfR9UPwyWbIpwOmpnzVizOlhePbtpsbbWK7Yg+7xOlWQicMW7LUZS
mEAEbzqC22HQEJ5g3npq6kx3oOyCpqmXq9VZq9xKqpDrqSR1N2r/Pr9qxDagC/f9
efIJ1mQkmjYax/dGsYf69vVq6kP2S2+mQYTBKOr3YU4uZ5olVkr4jiwstdMEKiUd
ki5aw2eByk6Q8x0geTakLtV4xw3KdF959QXMplMoOCAhOdeDiSFfQXqTV/nq1I/o
x0xeZPfYrbQAbFQ1ld6thkzQj720G2jTlmWBcQIDAQABAoIBAFUowkyK2ijR2CgF
T0OWlmN1iOeJ4UQE/ponDVVVruqllsxV62n0ST6fThEX/X3+IP5/68g1M4QrnxGn
KcZftLA9yZ0/6D0Lo5KkhbAW26sZHqJv8K2l+rz+MCs9Jyfq+79AGNNN01y9zN4r
ewF85PJLg/b9Mywie2wvffIvfPzapL2yDLyNT8T8pZXbvZZUFN8ZxJtlkNub1pzZ
LJGY9bsaE5jxQWQXlZ22+tmGHkWSOrOfKEnPFElAJFCqgYmpyWTpewTFjvlh667g
Eww5Bad/Deny5NOwQwR3EEWh2syxD7Kj5MrB+TBb6vbCHERm1BNWrwAWcy8Ik/AF
PwzUBL0CgYEA9pVUsmKqCA4tI9PjxnOzeQpoNegLggTYp/MC/K0n6SdJBPk7yY8Y
twN3G1ruk+hV5t1m3hBiYHr5sa/n3CdXzwgUuGW9vZrWtYJ041z45X+oZdGT4bcu
3nvMlqXiEaqiYsxTA1AfwikhMUsMP3BqMAdLgnshyCjrn8pZPoLAwYsCgYEA748Z
pClDaPba4fgmB6Kk9B0m/cRC87CxIK2Leqw8Kriiq3iVsq2hF2RxqGwJJ4NBpkg0
OyhC2754USiFvKiC6YpACKgTEPKbQrPf1eUXkAF/l7mdWsIvJt7ChfvF4xPkyLG3
ZK5BxMc96O0Yhzh8i1bk2nfynb1T6oCyyjgdsHMCgYEAz6M7qOLwLsxRMoQwn2G6
VUhwLERzvE58aiB1+XON0gUkta1xrO50b1fZqg1OLPpNq5PwFTpSvM+RBxEK+xWe
GVXCrOvvdIO4HSv3ZaVaaVav5N0v27e3Hd29j3WsAhhfmTZZCMcllwevTaTWcW0l
3b+m0/7/mV7r2qg3si3ERrUCgYEA1tO6R9flJrTw1uHkoMY/LNcTx1CARe62+ToI
MctQ7XLEFgc+H4zLQKIHtuSjVPbFIavwgvh49HybgxRW0jc/ptUe1WR8LJ+Tkj6i
RTt7ZN2jIVoH/YLULARp5yNAc4G8kimk77nBKwkNwNsWOvTx4zbaZfxY6xIEtfAR
5XxrS3cCgYEAuE6DD1NIsRbvvCo8v5Fcl85QioajtCBxWtD2m81wAvje/o2sCmq4
R90BeH6/bwyMQuMWsH2BFGMLGgCQ40kmVfMS3MCovQHgc52Fbpih7xPBR4MBNLxn
OKNaJnZowGs7CHq995DhqLjUV7PQ7kcXjCMsNI8Hpi/B+WfQVHmKN40=
-----END RSA PRIVATE KEY-----"""

pubkey = load_asymmetric_key_from_pem_bytestring(pem_public, key_algo="RSA_OAEP")
ciphertext_pycryptodome = _encrypt_via_rsa_oaep(plaintext, key_dict=dict(key=pubkey))
print("RSA PYCRYPTODOME CIPHERTEXT", ciphertext_pycryptodome)

##public_key_der = pem_to_der(pem_public, _lib.PUBLICKEY_TYPE)  USELESS
# print("RSA PUBLIC DER", public_key_der)
##cipher_public = RsaPublic(public_key_der, hash_type=HASH_TYPE_SHA512)

cipher_public = RsaPublic.from_pem(pem_public, hash_type=HASH_TYPE_SHA512)
ciphertext_wolfcrypt = {"ciphertext_chunks": [cipher_public.encrypt_oaep(plaintext)]}
print("RSA WOLFCRYPT CIPHERTEXT", ciphertext_wolfcrypt)

print("-------------")

wanted_ciphertext = ciphertext_pycryptodome  # OR ciphertext_wolfcrypt

privkey = load_asymmetric_key_from_pem_bytestring(pem_private, key_algo="RSA_OAEP")
decrypted = _decrypt_via_rsa_oaep(wanted_ciphertext, key_dict=dict(key=privkey))
print("RSA PYCRYPTODOME DECRYPTED", decrypted)

private_key_der = pem_to_der(pem_private, _lib.PRIVATEKEY_TYPE)
cipher_private = RsaPrivate(private_key_der, hash_type=HASH_TYPE_SHA512)
decrypted = cipher_private.decrypt_oaep(wanted_ciphertext["ciphertext_chunks"][0])
print("RSA CIPHERTEXT DECRYPTED", decrypted)


print("\n\n\n")
"""
sys.exit()
assert False
"""

### print(Sha256('wolfcrypt').hexdigest())


cipher_algo = "AES_CBC"


def _encrypt_via_aes_cbc_wolfcrypt(plaintext: bytes, key_dict: dict) -> dict:
    ciph = Aes(key=key_dict["key"], mode=MODE_CBC, IV=key_dict["iv"])
    plaintext_padded = pad_bytes(plaintext, block_size=AES_BLOCK_SIZE)
    ciphertext = ciph.encrypt(plaintext_padded)
    cipherdict = dict(ciphertext=ciphertext)
    return cipherdict


def _encrypt_bytestring_wolfcrypt(plaintext, cipher_algo, key_dict):
    if cipher_algo == "AES_CBC":
        encryptor = _encrypt_via_aes_cbc_wolfcrypt
    else:
        assert False
    return encryptor(plaintext, key_dict=key_dict)


key_dict = {
    "key": b"\x1a\x07\xf5\xe1A\x02\x12\xb6\xe0\n\x15\xd8~\xbe\xf3{\x9a\xc7\xd1=\x04\xf2\xe4R\xc4\x03fn\x10\xdf\x91\xe7",
    "iv": b"pQ\xd55\xda|lNR\xafxh\xbf\x8d\x121",
}  ##generate_symkey("AES_CBC")
print(">>>>>>> AES KEY DICT", key_dict)


res1 = encrypt_bytestring(plaintext=plaintext, cipher_algo=cipher_algo, key_dict=key_dict)
print(">>>>>>> PYCRYPTODOME AES CIPHERTEXT", res1)

res2 = _encrypt_bytestring_wolfcrypt(plaintext=plaintext, cipher_algo=cipher_algo, key_dict=key_dict)
print(">>>>>>> WOLFCRYPT AES CIPHERTEXT", res2)

assert res1 == res2, (res1, res2)

decrypted = decrypt_bytestring(cipherdict=res1, cipher_algo=cipher_algo, key_dict=key_dict)
assert decrypted == plaintext
print("SUCCESS")
