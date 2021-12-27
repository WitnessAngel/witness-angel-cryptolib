"""
This script requires memory-profiler and matplotlib to be installed!
"""

import io
import tempfile
from datetime import datetime, timezone
import time

from wacryptolib.cryptainer import CryptainerStorage, LOCAL_ESCROW_MARKER
from wacryptolib.sensor import TarfileRecordsAggregator

ENCRYPTION_CRYPTOCONF = dict(
    payload_encryption_layers=[
        dict(
            payload_encryption_algo="AES_EAX",
            key_encryption_layers=[dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],
            payload_signatures=[],
        ),
        dict(
            payload_encryption_algo="CHACHA20_POLY1305",
            key_encryption_layers=[
                dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER),
            ],
            payload_signatures=[],
        ),
        dict(
            payload_encryption_algo="AES_CBC",
            key_encryption_layers=[dict(key_encryption_algo="RSA_OAEP", key_escrow=LOCAL_ESCROW_MARKER)],
            payload_signatures=[],
        ),
    ]
)

from memory_profiler import profile
@profile(precision=4)
def profile_simple_encryption():

    tmp_path = tempfile.gettempdir()
    now = datetime.now(tz=timezone.utc)

    cryptainer_storage = CryptainerStorage(
        default_cryptoconf=ENCRYPTION_CRYPTOCONF,
        cryptainer_dir=tmp_path,
        offload_payload_ciphertext=True,
    )

    tarfile_aggregator = TarfileRecordsAggregator(cryptainer_storage=cryptainer_storage, max_duration_s=100)

    payload = b"abcdefghij" * 10 * 1024**2

    copy_payload = io.BytesIO(payload)

    tarfile_aggregator.add_record(sensor_name="dummy_sensor", from_datetime=now, to_datetime=now, extension=".bin", payload=payload)

    tarfile_aggregator._flush_aggregated_payload()

    time.sleep(10)




if __name__ == '__main__':
    profile_simple_encryption()
