import uuid
import itertools
import wacryptolib

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.PublicKey import RSA


def test_generate_keypair():
    """Cipher then decipher a message using RSA keypair"""

    uid = None
    binary_content = "Mon hât èst joli".encode('utf-8')

    keys = wacryptolib.generate_RSA_keypair(uid)
    public_key = keys["public_key"]
    private_key = keys["private_key"]

    # Cipher the binary content with the public key
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(binary_content)

    # Decipher it with the private key
    decipher = PKCS1_OAEP.new(private_key)
    deciphertext = decipher.decrypt(ciphertext)

    try:  # FIXME
        assert deciphertext == binary_content
        print("Successfuly done")
    except AssertionError:
        print("Problem cccured in the deciphering")


def test_generate_shared_secret():
    """Cipher then decipher a message using shared secret and RSA"""

    uid = uuid.uuid4()
    keys_count = 3
    threshold_count = 2
    combined_shares_list = []

    binary_content = "Mon hât èst joli".encode("utf-8")
    public_key_shares = wacryptolib.generate_private_key_shared_secret(uid, keys_count, threshold_count=threshold_count)
    shares_list = public_key_shares.get("shares")

    # Cipher the binary content
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key_shares["public_key"]))
    ciphertext = cipher.encrypt(binary_content)

    # Combine all the shares to make a list of bytes corresponding to the private key
    for slices in range(0, len(shares_list)):
        shares_tuple = [shares_list[slices][0], shares_list[slices][1], shares_list[slices][2]]
        combined_share = Shamir.combine(shares_tuple)
        combined_shares_list.append(combined_share)

    # Delete the values 0 we added at the end of the last tuple
    combined_shares_list[104] = bytes(iter(itertools.takewhile(lambda x: x != 0, combined_shares_list[104])))
    # padder avec des libs (bytes pad unpad)

    # Reconstruct the private key in type bytes
    chain = itertools.chain(combined_shares_list)
    private_key_reconstructed = b''.join(chain)

    # decipher the binary content
    decipher = PKCS1_OAEP.new(RSA.import_key(private_key_reconstructed))
    deciphertext = decipher.decrypt(ciphertext)

    try:
        assert binary_content == deciphertext
        print("Successfuly done")
    except AssertionError:
        print("Problem cccured in the deciphering")


if __name__ == '__main__':
    test_generate_shared_secret()
    test_generate_keypair()

