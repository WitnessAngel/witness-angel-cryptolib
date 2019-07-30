import processor
import random
import os
import uuid


def test_do_encrypt():
    plaintext = "Mon hât èst joli".encode("utf-8")
    container = processor._do_encrypt(plaintext)
