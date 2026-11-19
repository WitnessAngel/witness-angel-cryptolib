try:
    from random import SystemRandom, Random
except ImportError:  # MicroPython: no SystemRandom, and its random module (if any) is a seedable pseudo-random one

    import os

    class SystemRandom(object):
        '''Cryptographic random generator drawing from os.urandom(), with the methods that pkcs1 uses'''

        def getrandbits(self, k):
            return int.from_bytes(os.urandom((k + 7) // 8), "big") >> (-k % 8)

        def randint(self, a, b):
            span = b - a
            while True:  # Rejection sampling, to avoid modulo bias
                candidate = self.getrandbits(len(bin(span)) - 2)
                if candidate <= span:
                    return a + candidate

    Random = SystemRandom  # Only used by primality tests, which a cryptographic generator serves as well

default_crypto_random = SystemRandom()
default_pseudo_random = Random()
