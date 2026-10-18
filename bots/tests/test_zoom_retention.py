import io
import json
import logging
import threading
import uuid
from unittest.mock import Mock, patch

import requests
from django.db import close_old_connections
from django.test import Client, TransactionTestCase, override_settings
from django.utils import timezone

from bots.models import (
    ApiKey,
    AsyncTranscription,
    AudioChunk,
    Bot,
    BotChatMessageRequest,
    BotDebugScreenshot,
    BotEvent,
    BotEventTypes,
    BotLogEntry,
    BotMediaRequest,
    BotResourceSnapshot,
    BotStates,
    ChatMessage,
    ChatMessageToOptions,
    CreditTransaction,
    MediaBlob,
    Organization,
    Participant,
    ParticipantEvent,
    ParticipantEventTypes,
    Project,
    Recording,
    RecordingStates,
    Utterance,
    WebhookDeliveryAttempt,
    WebhookSubscription,
    WebhookTriggerTypes,
    ZoomMeetingToZoomOAuthConnectionMapping,
    ZoomOAuthApp,
    ZoomOAuthConnection,
    ZoomRemovalOperation,
    ZoomRemovalOperationPhases,
    ZoomRemovalOperationSources,
    ZoomRemovalOperationStates,
)
from bots.zoom_retention import (
    DatabaseVerificationError,
    StorageVerificationError,
    _delete_and_verify_storage,
    delete_expired_receipts,
    process_bot_purge,
)


def response(status_code, payload):
    result = Mock()
    result.status_code = status_code
    result.json.return_value = payload
    return result


class MemoryStorage:
    def __init__(self, names=(), delete_works=True):
        self.names = set(names)
        self.delete_works = delete_works

    def delete(self, name):
        if self.delete_works:
            self.names.discard(name)

    def exists(self, name):
        return name in self.names

    def listdir(self, prefix):
        prefix = prefix.rstrip("/") + "/"
        directories = set()
        files = set()
        for name in self.names:
            if not name.startswith(prefix):
                continue
            remainder = name[len(prefix) :]
            first, separator, _rest = remainder.partition("/")
            (directories if separator else files).add(first)
        return sorted(directories), sorted(files)


@override_settings(ENABLE_ZOOM_RETENTION_REMOVAL_API=True, LOG_BOT_STATE_CHANGES=False)
class ZoomRetentionTests(TransactionTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Retention Test Org")
        self.project = Project.objects.create(organization=self.organization, name="Project A")
        self.other_project = Project.objects.create(organization=self.organization, name="Project B")
        _api_key, self.api_key = ApiKey.create(self.project, "retention-a")
        _other_api_key, self.other_api_key = ApiKey.create(self.other_project, "retention-b")
        self.client = Client()

        self.zoom_app = ZoomOAuthApp.objects.create(project=self.project, client_id="client-a")
        self.zoom_app.set_credentials({"client_secret": "client-secret-a", "webhook_secret": "webhook-secret-a"})
        self.other_zoom_app = ZoomOAuthApp.objects.create(project=self.other_project, client_id="client-b")
        self.other_zoom_app.set_credentials({"client_secret": "client-secret-b", "webhook_secret": "webhook-secret-b"})

        self.webhook_patch = patch("bots.models.trigger_webhook", return_value=0)
        self.webhook_patch.start()

    def tearDown(self):
        self.webhook_patch.stop()

    def post(self, url, payload, api_key=None):
        return self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Token {api_key or self.api_key}",
        )

    def make_connection(self, *, other=False, refresh_token="refresh-secret"):
        app = self.other_zoom_app if other else self.zoom_app
        connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=app,
            user_id=f"user-{uuid.uuid4()}",
            account_id=f"account-{uuid.uuid4()}",
        )
        connection.set_credentials({"refresh_token": refresh_token})
        return connection

    def make_bot(self, *, state=BotStates.ENDED, other=False, name="Target"):
        project = self.other_project if other else self.project
        return Bot.objects.create(project=project, name=name, meeting_url="https://zoom.us/j/123456789", state=state)

    def revoke_payload(self, connection, operation_id=None, source=ZoomRemovalOperationSources.SKYTERRA_INITIATED, project=None):
        return {
            "project_id": (project or self.project).object_id,
            "operation_id": str(operation_id or uuid.uuid4()),
            "connection_id": connection.object_id,
            "source": source,
        }

    def purge_payload(self, *pairs, project=None):
        return {
            "project_id": (project or self.project).object_id,
            "targets": [{"operation_id": str(operation_id), "bot_id": bot.object_id} for operation_id, bot in pairs],
        }

    @patch("bots.zoom_retention.requests.post")
    def test_skyterra_revoke_is_terminal_only_after_definitive_provider_success(self, post):
        refresh_token = "unique-refresh-token-never-log"
        access_token = "unique-access-token-never-log"
        connection = self.make_connection(refresh_token=refresh_token)
        operation_id = uuid.uuid4()
        post.side_effect = [
            response(200, {"access_token": access_token, "refresh_token": "rotated-refresh-token"}),
            response(200, {"status": "success"}),
        ]

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logging.getLogger().addHandler(handler)
        try:
            result = self.post("/api/v1/zoom_retention/revoke", self.revoke_payload(connection, operation_id))
        finally:
            logging.getLogger().removeHandler(handler)

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["state"], ZoomRemovalOperationStates.REVOKED)
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())
        operation = ZoomRemovalOperation.objects.get(project=self.project, operation_id=operation_id)
        self.assertIsNone(operation.target_object_id)
        self.assertIsNotNone(operation.completed_at)
        self.assertIsNotNone(operation.expires_at)
        self.assertEqual(post.call_args_list[0].args[0], "https://zoom.us/oauth/token")
        self.assertEqual(post.call_args_list[1].args[0], "https://zoom.us/oauth/revoke")
        self.assertNotIn("?", post.call_args_list[1].args[0])
        rendered = result.content.decode() + stream.getvalue()
        self.assertNotIn(refresh_token, rendered)
        self.assertNotIn(access_token, rendered)

    @patch("bots.zoom_retention.requests.post")
    def test_ambiguous_network_revoke_is_not_success_and_keeps_credentials(self, post):
        marker = "ambiguous-secret-never-log"
        connection = self.make_connection(refresh_token=marker)
        encrypted_before = bytes(connection._encrypted_data)
        post.side_effect = [
            response(200, {"access_token": marker}),
            requests.Timeout(marker),
        ]
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logging.getLogger().addHandler(handler)
        try:
            result = self.post("/api/v1/zoom_retention/revoke", self.revoke_payload(connection))
        finally:
            logging.getLogger().removeHandler(handler)

        self.assertEqual(result.json()["state"], ZoomRemovalOperationStates.REVOKE_UNKNOWN)
        connection.refresh_from_db()
        self.assertEqual(bytes(connection._encrypted_data), encrypted_before)
        self.assertEqual(connection.state, 2)
        self.assertNotIn(marker, result.content.decode() + stream.getvalue())

    @patch("bots.zoom_retention.requests.post")
    def test_explicit_already_revoked_is_terminal_but_unrecognized_4xx_is_retryable(self, post):
        terminal = self.make_connection(refresh_token="terminal-refresh")
        post.return_value = response(400, {"code": 4741, "message": "token revoked"})
        terminal_result = self.post("/api/v1/zoom_retention/revoke", self.revoke_payload(terminal))
        self.assertEqual(terminal_result.json()["state"], ZoomRemovalOperationStates.REVOKED)
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=terminal.pk).exists())

        retryable = self.make_connection(refresh_token="retryable-refresh")
        post.return_value = response(400, {"error": "invalid_grant"})
        retryable_result = self.post("/api/v1/zoom_retention/revoke", self.revoke_payload(retryable))
        self.assertEqual(retryable_result.json()["state"], ZoomRemovalOperationStates.REVOKE_UNKNOWN)
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=retryable.pk).exists())

    @patch("bots.zoom_retention.requests.post")
    def test_signed_zoom_deauthorization_deletes_locally_without_provider_call(self, post):
        connection = self.make_connection()
        mapping = ZoomMeetingToZoomOAuthConnectionMapping.objects.create(
            zoom_oauth_connection=connection,
            zoom_oauth_app=self.zoom_app,
            meeting_id="123456789",
        )
        global_subscription = WebhookSubscription.objects.create(project=self.project, url="https://example.com/revoke-hook")
        delivery_attempt = WebhookDeliveryAttempt.objects.create(
            webhook_subscription=global_subscription,
            webhook_trigger_type=WebhookTriggerTypes.ZOOM_OAUTH_CONNECTION_STATE_CHANGE,
            idempotency_key=uuid.uuid4(),
            zoom_oauth_connection=connection,
            payload={"connection": connection.object_id},
        )
        result = self.post(
            "/api/v1/zoom_retention/revoke",
            self.revoke_payload(connection, source=ZoomRemovalOperationSources.ZOOM_DEAUTHORIZATION),
        )
        self.assertEqual(result.json()["state"], ZoomRemovalOperationStates.REVOKED)
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())
        self.assertFalse(ZoomMeetingToZoomOAuthConnectionMapping.objects.filter(pk=mapping.pk).exists())
        self.assertFalse(WebhookDeliveryAttempt.objects.filter(pk=delivery_attempt.pk).exists())
        self.assertTrue(WebhookSubscription.objects.filter(pk=global_subscription.pk).exists())
        post.assert_not_called()

    @patch("bots.zoom_retention.requests.post")
    def test_signed_deauthorization_settles_same_operation_after_ambiguous_revoke(self, post):
        connection = self.make_connection()
        operation_id = uuid.uuid4()
        post.side_effect = [response(200, {"access_token": "ephemeral-access"}), requests.Timeout()]
        first = self.post("/api/v1/zoom_retention/revoke", self.revoke_payload(connection, operation_id))
        self.assertEqual(first.json()["state"], ZoomRemovalOperationStates.REVOKE_UNKNOWN)
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())

        post.reset_mock()
        second = self.post(
            "/api/v1/zoom_retention/revoke",
            self.revoke_payload(connection, operation_id, source=ZoomRemovalOperationSources.ZOOM_DEAUTHORIZATION),
        )
        self.assertEqual(second.json()["state"], ZoomRemovalOperationStates.REVOKED)
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())
        post.assert_not_called()

    def test_cross_project_revoke_and_purge_create_no_receipt(self):
        foreign_connection = self.make_connection(other=True)
        revoke_operation_id = uuid.uuid4()
        revoke = self.post("/api/v1/zoom_retention/revoke", self.revoke_payload(foreign_connection, revoke_operation_id))
        self.assertEqual(revoke.status_code, 404)
        self.assertFalse(ZoomRemovalOperation.objects.filter(project=self.project, operation_id=revoke_operation_id).exists())
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=foreign_connection.pk).exists())

        local_bot = self.make_bot()
        foreign_bot = self.make_bot(other=True)
        purge_operation_id = uuid.uuid4()
        purge = self.post(
            "/api/v1/zoom_retention/purge",
            self.purge_payload((uuid.uuid4(), local_bot), (purge_operation_id, foreign_bot)),
        )
        self.assertEqual(purge.status_code, 404)
        self.assertEqual(ZoomRemovalOperation.objects.filter(project=self.project).count(), 0)
        self.assertTrue(Bot.objects.filter(pk=local_bot.pk).exists())
        self.assertTrue(Bot.objects.filter(pk=foreign_bot.pk).exists())

    @patch("bots.zoom_retention._delete_and_verify_storage", return_value=None)
    def test_active_bot_fails_closed_and_partial_batch_retries_only_incomplete_target(self, _storage):
        terminal = self.make_bot()
        active = self.make_bot(state=BotStates.JOINED_RECORDING)
        terminal_operation_id = uuid.uuid4()
        active_operation_id = uuid.uuid4()

        first = self.post(
            "/api/v1/zoom_retention/purge",
            self.purge_payload((terminal_operation_id, terminal), (active_operation_id, active)),
        )
        self.assertEqual([item["state"] for item in first.json()["results"]], ["purged", "pending_active"])
        self.assertFalse(Bot.objects.filter(pk=terminal.pk).exists())
        self.assertTrue(Bot.objects.filter(pk=active.pk).exists())

        Bot.objects.filter(pk=active.pk).update(state=BotStates.ENDED)
        second = self.post(
            "/api/v1/zoom_retention/purge",
            {
                "project_id": self.project.object_id,
                "targets": [
                    {"operation_id": str(terminal_operation_id), "bot_id": terminal.object_id},
                    {"operation_id": str(active_operation_id), "bot_id": active.object_id},
                ],
            },
        )
        self.assertEqual([item["state"] for item in second.json()["results"]], ["purged", "purged"])
        self.assertEqual(ZoomRemovalOperation.objects.get(operation_id=terminal_operation_id).attempt_count, 1)

    @patch("django.db.models.fields.files.FieldFile.delete", autospec=True)
    @patch("bots.zoom_retention._delete_and_verify_storage", return_value=None)
    def test_complete_dependent_purge_preserves_neighbor_and_project_global_state(self, _storage, file_delete):
        def clear_file(field_file, save=True):
            field_file.name = None
            if save:
                field_file.instance.save()

        file_delete.side_effect = clear_file
        target = self.make_bot(name="Delete me")
        neighbor = self.make_bot(name="Keep me")
        target_participant = Participant.objects.create(bot=target, uuid="target-person", full_name="Target Person")
        neighbor_participant = Participant.objects.create(bot=neighbor, uuid="neighbor-person", full_name="Neighbor Person")
        ParticipantEvent.objects.create(participant=target_participant, event_type=ParticipantEventTypes.JOIN, timestamp_ms=1)
        target_recording = Recording.objects.create(
            bot=target,
            recording_type=1,
            transcription_type=1,
            state=RecordingStates.COMPLETE,
            file="target-recording.mp4",
        )
        target_audio = AudioChunk.objects.create(
            recording=target_recording,
            participant=target_participant,
            audio_blob=b"audio",
            audio_blob_remote_file=f"audio-blobs/{target.object_id}-{target_recording.object_id}/audio-chunk-1.pcm",
            is_blob_stored_remotely=True,
            timestamp_ms=1,
            duration_ms=1,
            sample_rate=16000,
        )
        AsyncTranscription.objects.create(recording=target_recording)
        Utterance.objects.create(recording=target_recording, participant=target_participant, audio_chunk=target_audio, timestamp_ms=1, duration_ms=1)
        ChatMessage.objects.create(bot=target, participant=target_participant, text="private", to=ChatMessageToOptions.ONLY_BOT, timestamp=1)
        target_event = BotEvent.objects.create(bot=target, old_state=BotStates.ENDED, new_state=BotStates.ENDED, event_type=BotEventTypes.BOT_JOINED_MEETING)
        BotDebugScreenshot.objects.create(bot_event=target_event, file="target-shot.png")
        BotLogEntry.objects.create(bot=target, message="target log")
        BotChatMessageRequest.objects.create(bot=target, to="everyone", message="target outbound")
        BotResourceSnapshot.objects.create(bot=target, data={"private": True})

        shared_blob = MediaBlob.objects.create(project=self.project, blob=b"not-a-real-png", content_type="image/png", checksum="", duration_ms=0)
        target_request = BotMediaRequest.objects.create(bot=target, media_blob=shared_blob, media_type=1)
        neighbor_request = BotMediaRequest.objects.create(bot=neighbor, media_blob=shared_blob, media_type=1)
        global_subscription = WebhookSubscription.objects.create(project=self.project, url="https://example.com/hook")
        target_attempt = WebhookDeliveryAttempt.objects.create(
            webhook_subscription=global_subscription,
            webhook_trigger_type=WebhookTriggerTypes.BOT_STATE_CHANGE,
            idempotency_key=uuid.uuid4(),
            bot=target,
            payload={"meeting_url": target.meeting_url},
        )
        neighbor_attempt = WebhookDeliveryAttempt.objects.create(
            webhook_subscription=global_subscription,
            webhook_trigger_type=WebhookTriggerTypes.BOT_STATE_CHANGE,
            idempotency_key=uuid.uuid4(),
            bot=neighbor,
            payload={"safe": True},
        )
        credit = CreditTransaction.objects.create(
            organization=self.organization,
            centicredits_before=100,
            centicredits_after=90,
            centicredits_delta=-10,
            bot=target,
            description=f"For bot {target.object_id}",
        )

        operation_id = uuid.uuid4()
        result = self.post("/api/v1/zoom_retention/purge", self.purge_payload((operation_id, target)))
        self.assertEqual(result.json()["results"][0]["state"], ZoomRemovalOperationStates.PURGED)
        self.assertFalse(Bot.objects.filter(pk=target.pk).exists())
        self.assertFalse(WebhookDeliveryAttempt.objects.filter(pk=target_attempt.pk).exists())
        self.assertFalse(BotMediaRequest.objects.filter(pk=target_request.pk).exists())
        self.assertTrue(Bot.objects.filter(pk=neighbor.pk).exists())
        self.assertTrue(Participant.objects.filter(pk=neighbor_participant.pk).exists())
        self.assertTrue(WebhookSubscription.objects.filter(pk=global_subscription.pk).exists())
        self.assertTrue(WebhookDeliveryAttempt.objects.filter(pk=neighbor_attempt.pk).exists())
        self.assertTrue(BotMediaRequest.objects.filter(pk=neighbor_request.pk).exists())
        self.assertTrue(MediaBlob.objects.filter(pk=shared_blob.pk).exists())
        credit.refresh_from_db()
        self.assertIsNone(credit.bot_id)
        self.assertNotIn(target.object_id, credit.description)
        self.assertIn(result.json()["results"][0]["target_digest"], credit.description)

    def test_storage_deletion_removes_exact_objects_and_deterministic_audio_prefix(self):
        recording_storage = MemoryStorage(["recordings/target.mp4", "recordings/neighbor.mp4"])
        screenshot_storage = MemoryStorage(["shots/target.png", "shots/neighbor.png"])
        audio_storage = MemoryStorage(
            [
                "audio/target.pcm",
                "audio-blobs/bot-target-rec-target/audio-chunk-2.pcm",
                "audio-blobs/bot-target-rec-target/nested/audio-chunk-3.pcm",
                "audio-blobs/bot-neighbor-rec-neighbor/audio-chunk-4.pcm",
            ]
        )
        manifest = {
            "recordings": ["recordings/target.mp4"],
            "screenshots": ["shots/target.png"],
            "audio": ["audio/target.pcm"],
            "audio_prefixes": ["audio-blobs/bot-target-rec-target"],
        }
        with patch("bots.zoom_retention.storages", {"recordings": recording_storage, "bot_debug_screenshots": screenshot_storage, "audio_chunks": audio_storage}):
            _delete_and_verify_storage(manifest)

        self.assertEqual(recording_storage.names, {"recordings/neighbor.mp4"})
        self.assertEqual(screenshot_storage.names, {"shots/neighbor.png"})
        self.assertEqual(audio_storage.names, {"audio-blobs/bot-neighbor-rec-neighbor/audio-chunk-4.pcm"})

    def test_storage_verification_failure_is_retryable_and_does_not_delete_bot(self):
        bot = self.make_bot()
        operation_id = uuid.uuid4()
        with patch("bots.zoom_retention._delete_and_verify_storage", side_effect=StorageVerificationError()):
            first = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(first.state, ZoomRemovalOperationStates.PURGE_UNKNOWN)
        self.assertTrue(Bot.objects.filter(pk=bot.pk).exists())

        with patch("bots.zoom_retention._delete_and_verify_storage", return_value=None):
            second = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(second.state, ZoomRemovalOperationStates.PURGED)

    @patch("bots.zoom_retention._delete_and_verify_storage", return_value=None)
    def test_database_phase_failure_keeps_data_deleted_proof_and_retries(self, _storage):
        bot = self.make_bot()
        operation_id = uuid.uuid4()
        with patch("bots.zoom_retention._delete_bot_dependents_and_row", side_effect=DatabaseVerificationError()):
            first = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(first.state, ZoomRemovalOperationStates.DATA_DELETED)
        self.assertEqual(first.phase, ZoomRemovalOperationPhases.DATA_DELETED)
        self.assertTrue(Bot.objects.filter(pk=bot.pk).exists())

        second = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(second.state, ZoomRemovalOperationStates.PURGED)
        self.assertFalse(Bot.objects.filter(pk=bot.pk).exists())

    @patch("bots.zoom_retention._delete_and_verify_storage", return_value=None)
    def test_bot_row_delete_and_database_proof_phase_are_atomic(self, _storage):
        bot = self.make_bot()
        operation_id = uuid.uuid4()
        original_save = ZoomRemovalOperation.save

        def fail_database_proof_save(instance, *args, **kwargs):
            if instance.phase == ZoomRemovalOperationPhases.DATABASE_DELETED:
                raise RuntimeError("synthetic proof write failure")
            return original_save(instance, *args, **kwargs)

        with patch.object(ZoomRemovalOperation, "save", new=fail_database_proof_save):
            first = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(first.state, ZoomRemovalOperationStates.DATA_DELETED)
        self.assertEqual(first.phase, ZoomRemovalOperationPhases.DATA_DELETED)
        self.assertTrue(Bot.objects.filter(pk=bot.pk).exists())

        second = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(second.state, ZoomRemovalOperationStates.PURGED)

    @patch("bots.zoom_retention._delete_and_verify_storage", return_value=None)
    def test_existing_delete_data_phase_failure_is_retryable(self, _storage):
        bot = self.make_bot()
        operation_id = uuid.uuid4()
        original_delete_data = Bot.delete_data
        calls = 0

        def fail_once(instance):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("synthetic delete_data failure")
            return original_delete_data(instance)

        with patch.object(Bot, "delete_data", new=fail_once):
            first = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
            self.assertEqual(first.state, ZoomRemovalOperationStates.PURGE_UNKNOWN)
            self.assertEqual(first.phase, ZoomRemovalOperationPhases.STORAGE_VERIFIED)
            self.assertTrue(Bot.objects.filter(pk=bot.pk).exists())

            second = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(second.state, ZoomRemovalOperationStates.PURGED)

    def test_final_readback_failure_does_not_write_completion_receipt(self):
        bot = self.make_bot()
        operation_id = uuid.uuid4()
        with patch("bots.zoom_retention._delete_and_verify_storage", side_effect=[None, StorageVerificationError(), None]):
            first = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
            self.assertEqual(first.state, ZoomRemovalOperationStates.DATA_DELETED)
            self.assertEqual(first.phase, ZoomRemovalOperationPhases.DATABASE_DELETED)
            self.assertIsNone(first.completed_at)
            self.assertFalse(Bot.objects.filter(pk=bot.pk).exists())

            second = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(second.state, ZoomRemovalOperationStates.PURGED)

    @patch("bots.zoom_retention._delete_and_verify_storage", return_value=None)
    def test_response_loss_replay_and_project_scoped_readback_use_durable_receipt(self, _storage):
        bot = self.make_bot()
        operation_id = uuid.uuid4()
        first = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(first.state, ZoomRemovalOperationStates.PURGED)

        replay = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(replay.pk, first.pk)
        self.assertEqual(replay.attempt_count, 1)

        own_readback = self.client.get(
            f"/api/v1/zoom_retention/operations/{operation_id}",
            HTTP_AUTHORIZATION=f"Token {self.api_key}",
        )
        foreign_readback = self.client.get(
            f"/api/v1/zoom_retention/operations/{operation_id}",
            HTTP_AUTHORIZATION=f"Token {self.other_api_key}",
        )
        self.assertEqual(own_readback.json()["state"], ZoomRemovalOperationStates.PURGED)
        self.assertNotIn(bot.object_id, own_readback.content.decode())
        self.assertEqual(foreign_readback.status_code, 404)
        receipt = ZoomRemovalOperation.objects.get(pk=first.pk)
        self.assertIsNone(receipt.target_object_id)
        self.assertEqual(receipt.storage_manifest, {})

    @patch("bots.zoom_retention._delete_and_verify_storage", return_value=None)
    def test_missing_target_is_never_inferred_purged_without_receipt(self, _storage):
        operation_id = uuid.uuid4()
        result = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id="bot_missing123")
        self.assertEqual(result.state, ZoomRemovalOperationStates.NOT_FOUND_UNPROVED)
        self.assertIsNone(result.completed_at)
        replay = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id="bot_missing123")
        self.assertEqual(replay.state, ZoomRemovalOperationStates.NOT_FOUND_UNPROVED)

    def test_inflight_lease_makes_duplicate_request_non_destructive(self):
        bot = self.make_bot()
        operation_id = uuid.uuid4()
        entered = threading.Event()
        release = threading.Event()
        calls = 0
        calls_lock = threading.Lock()
        results = []

        def storage_step(_manifest):
            nonlocal calls
            with calls_lock:
                calls += 1
                current = calls
            if current == 1:
                entered.set()
                release.wait(timeout=10)

        def worker():
            close_old_connections()
            results.append(process_bot_purge(project=Project.objects.get(pk=self.project.pk), operation_id=operation_id, bot_object_id=bot.object_id))
            close_old_connections()

        with patch("bots.zoom_retention._delete_and_verify_storage", side_effect=storage_step):
            thread = threading.Thread(target=worker)
            thread.start()
            self.assertTrue(entered.wait(timeout=10))
            duplicate = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
            self.assertNotEqual(duplicate.state, ZoomRemovalOperationStates.PURGED)
            self.assertTrue(Bot.objects.filter(pk=bot.pk).exists())
            release.set()
            thread.join(timeout=20)

        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0].state, ZoomRemovalOperationStates.PURGED)
        self.assertEqual(ZoomRemovalOperation.objects.get(operation_id=operation_id).attempt_count, 1)

    def test_completed_receipt_expires_after_bounded_window(self):
        bot = self.make_bot()
        with patch("bots.zoom_retention._delete_and_verify_storage", return_value=None):
            operation = process_bot_purge(project=self.project, operation_id=uuid.uuid4(), bot_object_id=bot.object_id)
        self.assertGreater(operation.expires_at, operation.completed_at)
        ZoomRemovalOperation.objects.filter(pk=operation.pk).update(expires_at=timezone.now())
        self.assertEqual(delete_expired_receipts(), 1)
        self.assertFalse(ZoomRemovalOperation.objects.filter(pk=operation.pk).exists())


@override_settings(ENABLE_ZOOM_RETENTION_REMOVAL_API=False)
class ZoomRetentionDefaultOffTests(TransactionTestCase):
    def test_api_is_unreachable_when_feature_flag_is_off(self):
        organization = Organization.objects.create(name="Off Org")
        project = Project.objects.create(organization=organization, name="Off Project")
        _key, plain_key = ApiKey.create(project, "off")
        response = Client().post(
            "/api/v1/zoom_retention/purge",
            data=json.dumps({"project_id": project.object_id, "targets": []}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Token {plain_key}",
        )
        self.assertEqual(response.status_code, 404)
