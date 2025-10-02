import pem

pem_data = """"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkvHRJ3KYCiNsjFGBQOJT
Rbx4W/WJ7f5N8Jn+yKW08y/9ERMkcM9imqRDVr5oYMTvKxyxVSsWj39ClhOojTGG
ZdlT6vgwtKgi7yHniUED6yxaABs60kIMF6W2CfS0RCtZY5LjVQpPhxmX3fy1g6n+
MJ0Y9PvGWVqDaBnoCFm4t17n2YKqzKLSO13HZwEnpisV14cxwSuK/0x8hjwRZkod
rFWPt+e1iCtqr+a0y5pQjZkSS1LY6BDsVz83vkoGUqsDnyQ+v4fuc3vklX9Z91Dx
dSnSbxX8IwJJ7kQEUi3O/kO7bGPTmcWbRAuYbH/6rFkMafVcgeaLBZG6h3CGR6nH
IwIDAQAB
-----END PUBLIC KEY-----"""


certs = pem.parse(pem_data)
cert = certs[0]
print (">>>CERT", repr(cert))
print (">>>PAYLOAD", repr(cert.decoded_payload))  # USELESS BECAUSE NOT INTERPRETED