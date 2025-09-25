import rsa


public_key_pem_from_web = """-----BEGIN RSA PUBLIC KEY-----
MEgCQQCo9+BpMRYQ/dL3DS2CyJxRF+j6ctbT3/Qp84+KeFhnii7NT7fELilKUSnx
S30WAvQCCo2yU1orfgqr41mM70MBAgMBAAE=
-----END RSA PUBLIC KEY-----"""
public_key = rsa.PublicKey.load_pkcs1(public_key_pem_from_web)
print(">>>> public_key FROM WEB:", public_key)


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
public_key = rsa.PublicKey.load_pkcs1_openssl_pem(public_key_pem_from_wacryptolib)
print(">>>> public_key FROM WACRYPTOLIB:", public_key)

print("")

(bob_pub, bob_priv) = rsa.newkeys(512)
message = ("hello guys").encode("utf8")
ciphertext = rsa.encrypt(message, bob_pub)
print("ENCRYPTED MESSAGE:", repr(ciphertext))

decrypted_message = rsa.decrypt(ciphertext, bob_priv)
print("DECRYPTED MESSAGE:", repr(message.decode('utf8')))
