from wacryptolib.container import ContainerStorage


class FakeTestContainerStorage(ContainerStorage):
    """Fake class which bypasses encryption and forces filename unicity regardless fo datetime, to speed up tests..."""
    increment = 0
    def enqueue_file_for_encryption(self, filename_base, data):
        super().enqueue_file_for_encryption(filename_base + (".%03d" % self.increment), data)
        self.increment += 1
    def _encrypt_data_into_container(self, data):
        return data
    def _decrypt_data_from_container(self, container):
        return container


