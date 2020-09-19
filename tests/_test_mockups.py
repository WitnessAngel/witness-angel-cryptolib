from uuid import UUID

from wacryptolib.container import ContainerStorage


class FakeTestContainerStorage(ContainerStorage):
    """Fake class which bypasses encryption and forces filename unicity regardless of datetime, to speed up tests..."""

    increment = 0

    def enqueue_file_for_encryption(self, filename_base, data, metadata):
        super().enqueue_file_for_encryption(
            filename_base + (".%03d" % self.increment), data, metadata=metadata
        )
        self.increment += 1

    def _encrypt_data_into_container(self, data, metadata):
        return dict(a=33, data_ciphertext=data)

    def _decrypt_data_from_container(self, container):
        return container["data_ciphertext"]


class WildcardUuid(object):
    """Dummy UUID wildcard to compare data trees containing any UUID"""
    def __eq__(self, other):
        return isinstance(other, UUID)
