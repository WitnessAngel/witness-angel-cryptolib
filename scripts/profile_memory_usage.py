"""
This script requires memory-profiler and matplotlib to be installed!
"""

import io
import tempfile
from datetime import datetime, timezone
import time

from wacryptolib.container import ContainerStorage, LOCAL_ESCROW_MARKER
from wacryptolib.sensor import TarfileRecordsAggregator
from wacryptolib.utilities import synchronized


class PassthroughTarfileRecordsAggregator(TarfileRecordsAggregator):

    @synchronized
    def add_record(self, sensor_name: str, from_datetime, to_datetime, extension: str, data: bytes):

        filename = self._build_record_filename(
            sensor_name=sensor_name, from_datetime=from_datetime, to_datetime=to_datetime, extension=extension
        )
        self._container_storage.enqueue_file_for_encryption(
            filename_base=filename, data=data, metadata={}
        )

    @synchronized
    def finalize_tarfile(self):
        pass  # DO NOTHING



ENCRYPTION_CONF = dict(
    data_encryption_strata=[
        dict(
            data_encryption_algo="AES_EAX",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="CHACHA20_POLY1305",
            key_encryption_strata=[
                dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER),
            ],
            data_signatures=[],
        ),
        dict(
            data_encryption_algo="AES_CBC",
            key_encryption_strata=[dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],
            data_signatures=[],
        ),
    ]
)

from memory_profiler import profile
@profile(precision=4)
def profile_simple_encryption():

    tmp_path = tempfile.gettempdir()
    now = datetime.now(tz=timezone.utc)
    print(">>>>> PUTTING CONTAINERS IN", tmp_path)

    container_storage = ContainerStorage(
        default_encryption_conf=ENCRYPTION_CONF,
        containers_dir=tmp_path,
        offload_data_ciphertext=True,
    )

    tarfile_aggregator = PassthroughTarfileRecordsAggregator(container_storage=container_storage, max_duration_s=100)

    data = b"abcdefghij" * 10 * 1024**2

    copy_data = io.BytesIO(data)

    tarfile_aggregator.add_record(sensor_name="dummy_sensor", from_datetime=now, to_datetime=now, extension=".bin", data=data)

    ##tarfile_aggregator._flush_aggregated_data()

    time.sleep(10)




if __name__ == '__main__':
    profile_simple_encryption()
