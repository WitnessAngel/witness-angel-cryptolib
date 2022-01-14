"""
This script requires memory-profiler and matplotlib to be installed!
"""

import io
import tempfile
import time
from datetime import datetime, timezone

from wacryptolib.cryptainer import CryptainerStorage, LOCAL_KEYFACTORY_TRUSTEE_MARKER
from wacryptolib.sensor import TarfileRecordAggregator

CRYPTOCONF = dict(
    payload_cipher_layers=[
        dict(
            payload_cipher_algo="AES_EAX",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_signatures=[],
        ),
        dict(
            payload_cipher_algo="CHACHA20_POLY1305",
            key_cipher_layers=[
                dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER),
            ],
            payload_signatures=[],
        ),
        dict(
            payload_cipher_algo="AES_CBC",
            key_cipher_layers=[dict(key_cipher_algo="RSA_OAEP", key_cipher_trustee=LOCAL_KEYFACTORY_TRUSTEE_MARKER)],
            payload_signatures=[],
        ),
    ]
)

# REQUIRES "pip install memory_profiler"
from memory_profiler import profile
@profile(precision=4)
def profile_simple_encryption():

    tmp_path = tempfile.gettempdir()
    now = datetime.now(tz=timezone.utc)

    cryptainer_storage = CryptainerStorage(
        default_cryptoconf=CRYPTOCONF,
        cryptainer_dir=tmp_path,
        offload_payload_ciphertext=True,
    )

    tarfile_aggregator = TarfileRecordAggregator(cryptainer_storage=cryptainer_storage, max_duration_s=100)

    payload = b"abcdefghij" * 10 * 1024**2

    copy_payload = io.BytesIO(payload)  # To stress memory
    del copy_payload

    tarfile_aggregator.add_record(sensor_name="dummy_sensor", from_datetime=now, to_datetime=now, extension=".bin", payload=payload)

    tarfile_aggregator._flush_aggregated_data()

    time.sleep(10)




if __name__ == '__main__':
    profile_simple_encryption()
