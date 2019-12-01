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
        return data

    def _decrypt_data_from_container(self, container):
        return container
