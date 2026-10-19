from unittest.mock import patch

from botocore.exceptions import ClientError
from botocore.stub import Stubber
from django.test import SimpleTestCase
from storages.backends.s3 import S3Storage

from bots.zoom_retention import StorageVerificationError, _delete_and_verify_storage, _storage_object_exists


class S3VerificationTests(SimpleTestCase):
    def storage(self, overwrite=True):
        return S3Storage(bucket_name="test-bucket", access_key="synthetic", secret_key="synthetic", region_name="us-east-1", file_overwrite=overwrite, location="scope")

    def test_present_object_is_detected_in_both_overwrite_modes(self):
        for overwrite in (True, False):
            storage = self.storage(overwrite)
            with self.subTest(overwrite=overwrite), Stubber(storage.connection.meta.client) as stub:
                stub.add_response("head_object", {}, {"Bucket": "test-bucket", "Key": "scope/file.txt"})
                self.assertTrue(_storage_object_exists(storage, "file.txt"))
                stub.assert_no_pending_responses()

    def test_absence_requires_object_404_and_accessible_bucket(self):
        storage = self.storage()
        with Stubber(storage.connection.meta.client) as stub:
            stub.add_client_error("head_object", service_error_code="404", http_status_code=404, expected_params={"Bucket": "test-bucket", "Key": "scope/file.txt"})
            stub.add_response("head_bucket", {}, {"Bucket": "test-bucket"})
            self.assertFalse(_storage_object_exists(storage, "file.txt"))
            stub.assert_no_pending_responses()

    def test_unknown_object_or_bucket_fail_closed(self):
        for status in (403, 500, 503):
            storage = self.storage()
            with self.subTest(object_status=status), Stubber(storage.connection.meta.client) as stub:
                stub.add_client_error("head_object", http_status_code=status)
                with self.assertRaises(ClientError):
                    _storage_object_exists(storage, "file.txt")
        for status in (403, 404, 503):
            storage = self.storage()
            with self.subTest(bucket_status=status), Stubber(storage.connection.meta.client) as stub:
                stub.add_client_error("head_object", http_status_code=404)
                stub.add_client_error("head_bucket", http_status_code=status)
                with self.assertRaises(ClientError):
                    _storage_object_exists(storage, "file.txt")

    def test_noop_delete_cannot_verify_present_exact_object(self):
        for manifest_key in ("recordings", "screenshots", "audio"):
            storage = self.storage()
            aliases = dict.fromkeys(("recordings", "bot_debug_screenshots", "audio_chunks"), storage)
            with self.subTest(group=manifest_key), patch("bots.zoom_retention.storages", aliases), Stubber(storage.connection.meta.client) as stub:
                stub.add_response("delete_object", {}, {"Bucket": "test-bucket", "Key": "scope/file.txt"})
                stub.add_response("head_object", {}, {"Bucket": "test-bucket", "Key": "scope/file.txt"})
                with self.assertRaises(StorageVerificationError):
                    _delete_and_verify_storage({manifest_key: ["file.txt"]})
                stub.assert_no_pending_responses()

    def test_prefix_discovered_objects_receive_truthful_head(self):
        storage = self.storage()
        aliases = dict.fromkeys(("recordings", "bot_debug_screenshots", "audio_chunks"), storage)
        with patch("bots.zoom_retention.storages", aliases), patch("bots.zoom_retention._list_storage_tree", return_value=["prefix/file.txt"]), Stubber(storage.connection.meta.client) as stub:
            stub.add_response("delete_object", {}, {"Bucket": "test-bucket", "Key": "scope/prefix/file.txt"})
            stub.add_response("head_object", {}, {"Bucket": "test-bucket", "Key": "scope/prefix/file.txt"})
            with self.assertRaises(StorageVerificationError):
                _delete_and_verify_storage({"audio_prefixes": ["prefix"]})
            stub.assert_no_pending_responses()
