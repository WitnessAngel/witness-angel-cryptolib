import processor


def test_do_encrypt():
    plaintext = "Mon hât èst joli".encode("utf-8")
    container = processor._do_encrypt(plaintext)
    plaintext_deciphered = processor._do_decrypt(container)
    assert plaintext == plaintext_deciphered


# def test_media_file():
#     input_medium = "cute.jpg"
#     processor.encrypt(input_medium)
