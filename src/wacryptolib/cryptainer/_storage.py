# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later

from concurrent.futures.thread import ThreadPoolExecutor
from datetime import timezone, datetime, timedelta
from pathlib import Path
import threading
from typing import Optional
import uuid

from wacryptolib.cryptainer import CRYPTAINER_SUFFIX, CRYPTAINER_TEMP_SUFFIX, CRYPTAINER_DATETIME_LENGTH, \
    CRYPTAINER_DATETIME_FORMAT, logger, get_cryptainer_size_on_filesystem, load_cryptainer_from_filesystem, \
    decrypt_payload_from_cryptainer, check_cryptainer_sanity, delete_cryptainer_from_filesystem, \
    encrypt_payload_and_stream_cryptainer_to_filesystem, encrypt_payload_into_cryptainer, dump_cryptainer_to_filesystem, \
    is_cryptainer_cryptoconf_streamable, CryptainerEncryptionPipeline, _get_offloaded_file_path
from wacryptolib.keystore import KeystorePoolBase
from wacryptolib.utilities import get_utc_now_date, is_file_basename, catch_and_log_exception, synchronized


class ReadonlyCryptainerStorage:
    """
    This class provides read access to a directory filled with cryptainers..

    :param cryptainer_dir: the folder where cryptainer files are stored
    :param keystore_pool: optional KeystorePool, which might be required by current cryptoconf
    """

    def __init__(self, cryptainer_dir: Path, keystore_pool: Optional[KeystorePoolBase] = None):
        cryptainer_dir = Path(cryptainer_dir).absolute()
        assert cryptainer_dir.is_dir(), cryptainer_dir
        self._cryptainer_dir = cryptainer_dir
        self._keystore_pool = keystore_pool  # Might be None, in this case fallback to in-memory pool

    def get_cryptainer_count(self, finished=True):
        return len(self.list_cryptainer_names(as_absolute_paths=True, finished=finished))  # Fastest version

    def list_cryptainer_names(
        self, as_sorted_list: bool = False, as_absolute_paths: bool = False, finished=True
    ):  # FIXME add function annotations everywhere in this class
        """Returns the list of encrypted cryptainers present in storage,
        sorted by name or not, absolute or not, as Path objects.

        If `finished` ìs None, both finished and pending cryptainers are listed.
        """
        assert self._cryptainer_dir.is_absolute(), self._cryptainer_dir
        paths = []  # Result as list, for multiple looping on it
        if finished is None or finished:
            paths += list(self._cryptainer_dir.glob("*" + CRYPTAINER_SUFFIX))
        if not finished:  # None or False
            paths += list(self._cryptainer_dir.glob("*" + CRYPTAINER_SUFFIX + CRYPTAINER_TEMP_SUFFIX))
        assert all(p.is_absolute() for p in paths), paths
        if as_sorted_list:
            paths = sorted(paths)
        if not as_absolute_paths:
            paths = [Path(p.name) for p in paths]  # Beware, it only works since we don't have subfolders for now!
        assert isinstance(paths, list), paths
        return paths

    def _get_cryptainer_datetime_utc(self, cryptainer_name):
        """Returns an UTC datetime corresponding to the creation time stored in filename, or else the file-stat mtime"""
        try:
            dt = datetime.strptime(cryptainer_name.name[:CRYPTAINER_DATETIME_LENGTH], CRYPTAINER_DATETIME_FORMAT)
            dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            logger.debug("Couldn't recognize timestamp in filename %s, falling back to file time", cryptainer_name.name)
            mtime = (
                self._make_absolute(cryptainer_name).stat().st_mtime
            )  # FIXME - Might fail if file got deleted concurrently
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        return dt

    def _get_cryptainer_size(self, cryptainer_name):
        """Returns a size in bytes"""
        return get_cryptainer_size_on_filesystem(self._make_absolute(cryptainer_name))

    def list_cryptainer_properties(
        self,
        as_sorted_list=False,
        with_creation_datetime=False,
        with_age=False,
        with_size=False,
        with_offloaded=False,
        finished=True,
    ):
        """Returns an list of dicts (unsorted by default) having the fields "name", [age] and [size], depending on requested properties."""
        cryptainer_names = self.list_cryptainer_names(
            as_sorted_list=as_sorted_list, as_absolute_paths=False, finished=finished
        )

        now = get_utc_now_date()

        result = []
        for cryptainer_name in cryptainer_names:
            entry = dict(name=cryptainer_name)
            if with_age or with_creation_datetime:
                creation_datetime = self._get_cryptainer_datetime_utc(cryptainer_name)
                if with_creation_datetime:
                    entry["creation_datetime"] = creation_datetime
                if with_age:
                    entry["age"] = now - creation_datetime  # We keep it as timedelta
            if with_size:
                entry["size"] = self._get_cryptainer_size(cryptainer_name)
            if with_offloaded:
                entry["offloaded"] = _get_offloaded_file_path(self._make_absolute(cryptainer_name)).is_file()
            result.append(entry)
        return result

    def is_valid_cryptainer_name(self, cryptainer_name):
        cryptainer_path = self._make_absolute(cryptainer_name)
        return cryptainer_path.is_file()

    def _make_absolute(self, cryptainer_name):
        assert is_file_basename(cryptainer_name), cryptainer_name
        return self._cryptainer_dir.joinpath(cryptainer_name)

    def load_cryptainer_from_storage(self, cryptainer_name_or_idx, include_payload_ciphertext=True) -> dict:
        """
        Return the encrypted cryptainer dict for `cryptainer_name_or_idx` (which must be in `list_cryptainer_names()`,
        or an index suitable for this sorted list).

        Only FINISHED cryptainers are expected to be loaded.
        """
        if isinstance(cryptainer_name_or_idx, int):
            cryptainer_names = self.list_cryptainer_names(as_sorted_list=True, as_absolute_paths=False, finished=True)
            cryptainer_name = cryptainer_names[cryptainer_name_or_idx]  # Will break if idx is out of bounds
        else:
            assert isinstance(cryptainer_name_or_idx, (Path, str)), repr(cryptainer_name_or_idx)
            cryptainer_name = Path(cryptainer_name_or_idx)
        assert not cryptainer_name.is_absolute(), cryptainer_name

        logger.info(
            "Loading cryptainer %s from storage (include_payload_ciphertext=%s)",
            cryptainer_name,
            include_payload_ciphertext,
        )
        cryptainer_filepath = self._make_absolute(cryptainer_name)
        cryptainer = load_cryptainer_from_filesystem(
            cryptainer_filepath, include_payload_ciphertext=include_payload_ciphertext
        )
        return cryptainer

    def decrypt_cryptainer_from_storage(
        self,
        cryptainer_name_or_idx,
        passphrase_mapper: Optional[dict] = None,
        verify_integrity_tags: bool = True,
        gateway_urls: Optional[list] = None,
        revelation_requestor_uid: Optional[uuid.UUID] = None,
    ) -> tuple:
        """
        Return the decrypted content of the cryptainer `cryptainer_name_or_idx` (which must be in `list_cryptainer_names()`,
        or an index suitable for this sorted list).
        """
        logger.info("Decrypting cryptainer %r from storage", cryptainer_name_or_idx)

        cryptainer = self.load_cryptainer_from_storage(cryptainer_name_or_idx, include_payload_ciphertext=True)

        medium_content, operation_report = self._decrypt_payload_from_cryptainer(
            cryptainer,
            passphrase_mapper=passphrase_mapper,
            verify_integrity_tags=verify_integrity_tags,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )
        if medium_content is None:
            logger.error("Storage cryptainer %s decryption failed", cryptainer_name_or_idx)
        else:
            logger.info("Storage cryptainer %s successfully decrypted", cryptainer_name_or_idx)
        return medium_content, operation_report

    def _decrypt_payload_from_cryptainer(
        self,
        cryptainer: dict,
        passphrase_mapper: Optional[dict],
        verify_integrity_tags: bool,
        gateway_urls: Optional[list] = None,
        revelation_requestor_uid: Optional[uuid.UUID] = None,
    ) -> tuple:
        return decrypt_payload_from_cryptainer(
            cryptainer,
            keystore_pool=self._keystore_pool,
            passphrase_mapper=passphrase_mapper,
            verify_integrity_tags=verify_integrity_tags,
            gateway_urls=gateway_urls,
            revelation_requestor_uid=revelation_requestor_uid,
        )  # Will fail if authorizations are not OK

    def check_cryptainer_sanity(self, cryptainer_name_or_idx):
        """Allows the validation of a cryptainer structure"""
        cryptainer = self.load_cryptainer_from_storage(cryptainer_name_or_idx, include_payload_ciphertext=True)

        check_cryptainer_sanity(cryptainer=cryptainer, jsonschema_mode=False)


class CryptainerStorage(ReadonlyCryptainerStorage):
    """
    This class encrypts file streams and stores them into filesystem, in a thread-safe way.

    Exceeding cryptainers are automatically purged when enqueuing new files or waiting for idle state.
    A thread pool is used to encrypt files in the background.

    :param cryptainers_dir: the folder where cryptainer files are stored
    :param keystore_pool: optional KeystorePool, which might be required by current cryptoconf
    :param default_cryptoconf: cryptoconf to use when none is provided when enqueuing payload
    :param max_cryptainer_quota: if set, cryptainers are deleted if they exceed this size in bytes
    :param max_cryptainer_count: if set, oldest exceeding cryptainers (time taken from their name, else their file-stats) are automatically erased
    :param max_cryptainer_age: if set, cryptainers exceeding this age (taken from their name, else their file-stats) in days are automatically erased
    :param max_workers: count of worker threads to use in parallel
    :param offload_payload_ciphertext: whether actual encrypted payload must be kept separated from structured cryptainer file
    """

    def __init__(
        self,
        cryptainer_dir: Path,
        keystore_pool: Optional[KeystorePoolBase] = None,
        default_cryptoconf: Optional[dict] = None,
        max_cryptainer_quota: Optional[int] = None,
        max_cryptainer_count: Optional[int] = None,
        max_cryptainer_age: Optional[timedelta] = None,
        max_workers: int = 1,
        offload_payload_ciphertext=True,
    ):
        super().__init__(cryptainer_dir=cryptainer_dir, keystore_pool=keystore_pool)
        assert max_cryptainer_quota is None or max_cryptainer_quota >= 0, max_cryptainer_quota
        assert max_cryptainer_count is None or max_cryptainer_count >= 0, max_cryptainer_count
        assert max_cryptainer_age is None or max_cryptainer_age >= timedelta(seconds=0), max_cryptainer_age
        self._default_cryptoconf = default_cryptoconf
        self._max_cryptainer_quota = max_cryptainer_quota
        self._max_cryptainer_count = max_cryptainer_count
        self._max_cryptainer_age = max_cryptainer_age
        self._thread_pool_executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="cryptainer_worker")
        self._pending_executor_futures = []
        self._lock = threading.Lock()
        self._offload_payload_ciphertext = offload_payload_ciphertext

    def __del__(self):
        self._thread_pool_executor.shutdown(wait=False)

    def _delete_cryptainer(self, cryptainer_name):
        cryptainer_filepath = self._make_absolute(cryptainer_name)
        logger.info("Deleting cryptainer %s", cryptainer_filepath)
        delete_cryptainer_from_filesystem(cryptainer_filepath)

    def delete_cryptainer(self, cryptainer_name):
        logger.info("Intentionally deleting cryptainer %s" % cryptainer_name)
        self._delete_cryptainer(cryptainer_name=cryptainer_name)

    def purge_exceeding_cryptainers(self) -> int:  # FIXME test this shortcut
        logger.info("Intentionally purging cryptainers")
        return self._purge_exceeding_cryptainers()

    def _purge_exceeding_cryptainers(self) -> int:
        """Purge cryptainers first by date, then total quota, then count, depending on instance settings.

        Unfinished cryptainers are, for now, ALWAYS included in the purge, since we assume they are forsaken
        if they are still pending at this time.
        """

        deleted_cryptainer_count = 0

        if self._max_cryptainer_age is not None:  # FIRST these, since their deletion is unconditional
            cryptainer_dicts = self.list_cryptainer_properties(with_age=True, finished=None)
            for cryptainer_dict in cryptainer_dicts:
                ##print("COMPARING", cryptainer_dict["age"], self._max_cryptainer_age)
                if cryptainer_dict["age"] > self._max_cryptainer_age:
                    logger.info("Deleting cryptainer %s due to age", cryptainer_dict["name"])
                    self._delete_cryptainer(cryptainer_dict["name"])
                    deleted_cryptainer_count += 1

        if self._max_cryptainer_quota is not None:
            max_cryptainer_quota = self._max_cryptainer_quota

            cryptainer_dicts = self.list_cryptainer_properties(with_size=True, with_age=True, finished=None)
            cryptainer_dicts.sort(key=lambda x: (-x["age"], x["name"]), reverse=True)  # Oldest last

            total_space_consumed = sum(x["size"] for x in cryptainer_dicts)

            while total_space_consumed > max_cryptainer_quota:
                deleted_cryptainer_dict = cryptainer_dicts.pop()
                logger.info("Deleting cryptainer %s due to lack of storage space", deleted_cryptainer_dict["name"])
                self._delete_cryptainer(deleted_cryptainer_dict["name"])
                total_space_consumed -= deleted_cryptainer_dict["size"]
                deleted_cryptainer_count += 1

        if self._max_cryptainer_count is not None:
            cryptainer_dicts = self.list_cryptainer_properties(with_age=True, finished=None)
            cryptainers_count = len(cryptainer_dicts)

            if cryptainers_count > self._max_cryptainer_count:
                assert cryptainers_count > 0, cryptainers_count
                excess_count = cryptainers_count - self._max_cryptainer_count
                cryptainer_dicts.sort(key=lambda x: (-x["age"], x["name"]))  # Oldest first
                deleted_cryptainer_dicts = cryptainer_dicts[:excess_count]
                for deleted_cryptainer_dict in deleted_cryptainer_dicts:
                    logger.info(
                        "Deleting cryptainer %s due to excessive count of cryptainers", deleted_cryptainer_dict["name"]
                    )
                    self._delete_cryptainer(deleted_cryptainer_dict["name"])
                    deleted_cryptainer_count += 1

        return deleted_cryptainer_count

    def _encrypt_payload_and_stream_cryptainer_to_filesystem(
        self, payload, cryptainer_filepath, cryptainer_metadata, cryptoconf
    ):
        assert cryptoconf, cryptoconf
        encrypt_payload_and_stream_cryptainer_to_filesystem(
            cryptainer_filepath=cryptainer_filepath,
            payload=payload,
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            keystore_pool=self._keystore_pool,
        )

    def _encrypt_payload_into_cryptainer(self, payload, cryptainer_metadata, cryptoconf):
        assert cryptoconf, cryptoconf
        return encrypt_payload_into_cryptainer(
            payload=payload,
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            keystore_pool=self._keystore_pool,
        )

    def _do_encrypt_payload_and_dump_cryptainer(self, filename_base, payload, cryptainer_metadata, cryptoconf) -> str:
        # TODO later as a SKIP here!
        # if not payload:
        #    logger.warning("Skipping encryption of empty payload payload for file %s", filename_base)
        #    return
        assert cryptoconf, cryptoconf

        cryptainer_filepath = self._make_absolute(filename_base + CRYPTAINER_SUFFIX)

        if self._use_streaming_encryption_for_cryptoconf(cryptoconf):
            # We can use newer, low-memory, streamed API
            logger.debug(
                "Encrypting payload file %r into offloaded cryptainer directly streamed to storage file %s",
                filename_base,
                cryptainer_filepath,
            )
            # import logging_tree
            # logging_tree.printout()
            self._encrypt_payload_and_stream_cryptainer_to_filesystem(
                payload,
                cryptainer_filepath=cryptainer_filepath,
                cryptainer_metadata=cryptainer_metadata,
                cryptoconf=cryptoconf,
            )

        else:
            # We use legacy API which encrypts all and then dumps all
            logger.debug("Encrypting payload file to self-sufficient cryptainer %r", filename_base)
            # Memory warning: duplicates payload to json-compatible cryptainer
            cryptainer = self._encrypt_payload_into_cryptainer(
                payload,
                cryptainer_metadata=cryptainer_metadata,
                cryptoconf=cryptoconf,
            )
            logger.debug("Writing self-sufficient cryptainer payload to storage file %s", cryptainer_filepath)
            dump_cryptainer_to_filesystem(
                cryptainer_filepath, cryptainer=cryptainer, offload_payload_ciphertext=self._offload_payload_ciphertext
            )

        logger.info("Data file %r successfully encrypted into storage cryptainer", filename_base)
        return cryptainer_filepath.name

    @catch_and_log_exception("CryptainerStorage._offloaded_encrypt_payload_and_dump_cryptainer")
    def _offloaded_encrypt_payload_and_dump_cryptainer(self, filename_base, payload, cryptainer_metadata, cryptoconf):
        """Task to be called by background thread, which encrypts a payload into a disk cryptainer.

        Returns the cryptainer basename."""
        assert filename_base, repr(filename_base)
        self._do_encrypt_payload_and_dump_cryptainer(
            filename_base=filename_base,
            payload=payload,
            cryptainer_metadata=cryptainer_metadata,
            cryptoconf=cryptoconf,
        )
        return None

    def _use_streaming_encryption_for_cryptoconf(self, cryptoconf):
        return self._offload_payload_ciphertext and is_cryptainer_cryptoconf_streamable(cryptoconf)

    def _resolve_cryptoconf(self, cryptoconf):
        cryptoconf = cryptoconf or self._default_cryptoconf
        if not cryptoconf:
            raise RuntimeError("Either default or file-specific cryptoconf must be provided to CryptainerStorage")
        return cryptoconf

    def _cleanup_before_new_record_encryption(self):
        """
        Validate arguments for new encryption, and purge obsolete things in storage.
        """
        self._purge_exceeding_cryptainers()
        self._purge_executor_results()

    @synchronized
    def create_cryptainer_encryption_stream(
        self,
        filename_base,
        cryptainer_metadata,
        signature_policy: Optional[str],
        cryptoconf=None,
        dump_initial_cryptainer=True,
        cryptainer_encryption_stream_class=None,
        cryptainer_encryption_stream_extra_kwargs=None,
    ):
        """
        Create and return a cryptainer encryption stream.

        Purges exceeding cryptainers and pending results beforehand.
        """

        cryptainer_encryption_stream_class = cryptainer_encryption_stream_class or CryptainerEncryptionPipeline
        cryptainer_encryption_stream_extra_kwargs = cryptainer_encryption_stream_extra_kwargs or {}

        logger.debug("Building cryptainer stream %r", filename_base)
        cryptainer_filepath = self._make_absolute(filename_base + CRYPTAINER_SUFFIX)
        cryptoconf = self._resolve_cryptoconf(cryptoconf)
        self._cleanup_before_new_record_encryption()

        cryptainer_encryption_stream = cryptainer_encryption_stream_class(
            cryptainer_filepath,
            cryptoconf=cryptoconf,
            cryptainer_metadata=cryptainer_metadata,
            signature_policy=signature_policy,
            keystore_pool=self._keystore_pool,
            dump_initial_cryptainer=dump_initial_cryptainer,
            **cryptainer_encryption_stream_extra_kwargs,
        )
        return cryptainer_encryption_stream

    @synchronized
    def enqueue_file_for_encryption(
        self,
        filename_base,
        payload,
        cryptainer_metadata,
        cryptoconf=None,  # TODO add "wait/syncrhonous" argument ?
    ):
        """Enqueue a payload for asynchronous encryption and storage.

        Purges exceeding cryptainers and pending results beforehand.

        The filename of final cryptainer might be different from provided one.
        Deware, target cryptainer with the same constructed name might be overwritten.

        :param payload: Bytes string, or a file-like object open for reading, which will be automatically closed.
        :param cryptainer_metadata: Dict of metadata added (unencrypted) to cryptainer.
        :param keychain_uid: If provided, replaces autogenerated default keychain_uid for this cryptainer.
        :param cryptoconf: If provided, replaces default cryptoconf for this cryptainer.
        """
        assert is_file_basename(filename_base), filename_base
        logger.info("Enqueuing file %r for encryption and storage", filename_base)

        cryptoconf = self._resolve_cryptoconf(cryptoconf)
        self._cleanup_before_new_record_encryption()

        future = self._thread_pool_executor.submit(
            self._offloaded_encrypt_payload_and_dump_cryptainer,
            filename_base=filename_base,
            payload=payload,
            cryptainer_metadata=cryptainer_metadata,
            cryptoconf=cryptoconf,
        )
        self._pending_executor_futures.append(future)

    def encrypt_file(  # FIXME find more meaningful name?
        self, filename_base, payload, cryptainer_metadata, cryptoconf=None
    ) -> str:
        """Synchronously encrypt the provided payload into cryptainer storage.

        Does NOT purge exceeding cryptainers and pending results beforehand.

        Returns the cryptainer basename."""
        assert is_file_basename(filename_base), filename_base
        cryptoconf = self._resolve_cryptoconf(cryptoconf)
        return self._do_encrypt_payload_and_dump_cryptainer(
            filename_base=filename_base,
            payload=payload,
            cryptainer_metadata=cryptainer_metadata,
            cryptoconf=cryptoconf,
        )

    def _purge_executor_results(self):
        """Remove futures which are actually over. We don't care about their result/exception here"""
        still_pending_results = [future for future in self._pending_executor_futures if not future.done()]
        self._pending_executor_futures = still_pending_results

    @synchronized
    def wait_for_idle_state(self):
        """Wait for each pending future to be completed."""
        self._purge_executor_results()
        for future in self._pending_executor_futures:
            future.result()  # Should NEVER raise, thanks to the @catch_and_log_exception above, and absence of cancellations
        self._purge_exceeding_cryptainers()  # Good to have now
