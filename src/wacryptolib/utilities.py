from typing import List

from Crypto.Util.Padding import pad, unpad


def split_as_padded_chunks(bytestring: bytes, chunk_size: int) -> List[bytes]:
    """Collect a `bytestring` into chunks or blocks of size defined by `chunk_size` and
        pad the last chunk when there isn't enough values initially

        :param bytestring: bytestring which have to be split into chunks
        :param chunk_size: size of a chunk

        :return: list of padded chunks in bytes"""

    chunks = []
    for i in range((len(bytestring) + chunk_size - 1) // chunk_size):
        chunk = [bytestring[i * chunk_size : (i + 1) * chunk_size]]
        if len(chunk[0]) != chunk_size:
            chunks.append(pad(chunk[0], chunk_size))
        else:
            chunks.append(chunk[0])
    return chunks
