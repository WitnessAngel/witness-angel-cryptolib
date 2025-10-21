import hashlib

import pkcs1.rsaes_oaep
import pkcs1.keys

message = "OK".encode("utf8")


#### HACK
import rsa
'''
public_key_pem_from_wacryptolib = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvHRJ3KYCiNsjFGBQOJT
Rbx4W/WJ7f5N8Jn+yKW08y/9ERMkcM9imqRDVr5oYMTvKxyxVSsWj39ClhOojTGG
ZdlT6vgwtKgi7yHniUED6yxaABs60kIMF6W2CfS0RCtZY5LjVQpPhxmX3fy1g6n+
MJ0Y9PvGWVqDaBnoCFm4t17n2YKqzKLSO13HZwEnpisV14cxwSuK/0x8hjwRZkod
rFWPt+e1iCtqr+a0y5pQjZkSS1LY6BDsVz83vkoGUqsDnyQ+v4fuc3vklX9Z91Dx
dSnSbxX8IwJJ7kQEUi3O/kO7bGPTmcWbRAuYbH/6rFkMafVcgeaLBZG6h3CGR6nH
IwIDAQAB
-----END PUBLIC KEY-----
"""
_public_key_otherformat = rsa.PublicKey.load_pkcs1_openssl_pem(public_key_pem_from_wacryptolib)
'''
(bob_pub, bob_priv) = rsa.newkeys(4096)  # Gives (PublicKey(n, e), PrivateKey(n, e, d, p, q))

print("P:", bob_priv.p)
print("Q:", bob_priv.q)

AAAAAA
if False:
    # VALUES imported from a wacryptolib PEM file
    n = 18550036936074777576745860692222929823309849339732419768654179699291152139495559922834976621735536311921517873134983260454935762117010713780022370715702782337501169317789855286485787891194144971453027165749472806656521816427794317257818177125547356250896811776665398428028265103962501107999670516354789549043186362295800968855400059275817415069429507150398646058973164280273097890283834820569305921523093272920020136655934918036481615681408018554452207478475696785278942743360661011323663161746160689975622147380453637216164274299383628735318891050050778834528526183812215083531500158856576001965730296948614878578467
    e = 65537

    public_key = pkcs1.keys.RsaPublicKey(n, e)



    ciphertext = pkcs1.rsaes_oaep.encrypt(public_key, message, label=b'', hash_class=hashlib.sha512)
                                        # TODO: mgf=mgf.mgf1, seed=None, rnd=default_crypto_random))

    print("ENCRYPTED MESSAGE:", repr(ciphertext))



##public, private = pkcs1.keys.generate_key_pair(size=4096)
public = pkcs1.keys.RsaPublicKey(bob_pub.n, bob_pub.e)
private = pkcs1.keys.RsaPrivateKey(bob_priv.n, bob_priv.d)

print("MESSAGE", message)

ciphertext = pkcs1.rsaes_oaep.encrypt(public, message=message, label=b'', hash_class=hashlib.sha256)
                                    # TODO: mgf=mgf.mgf1, seed=None, rnd=default_crypto_random))
print("ENCRYPTED MESSAGE:", repr(ciphertext))

cleartext = pkcs1.rsaes_oaep.decrypt(private, message=ciphertext, label=b'', hash_class=hashlib.sha256)
                                    # TODO: mgf=mgf.mgf1, seed=None, rnd=default_crypto_random))
print("DECRYPTED MESSAGE:", repr(cleartext))