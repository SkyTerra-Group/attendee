import hashlib
import io
import json
import logging
import threading
import uuid
from datetime import timedelta
from unittest.mock import Mock, patch

import requests
from concurrency.exceptions import RecordModifiedError
from django.core.exceptions import ValidationError
from django.db import close_old_connections, transaction
from django.test import Client, TransactionTestCase, override_settings
from django.utils import timezone

from bots.bot_runtime_fence import bot_runtime_is_absent
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
    ZoomOAuthConnectionStates,
    ZoomRemovalOperation,
    ZoomRemovalOperationPhases,
    ZoomRemovalOperationSources,
    ZoomRemovalOperationStates,
    ZoomRemovalOperationTypes,
)
from bots.tasks.launch_scheduled_bot_task import launch_scheduled_bot
from bots.tasks.refresh_zoom_oauth_connection_task import refresh_zoom_oauth_connection
from bots.tasks.sync_zoom_oauth_connection_task import sync_zoom_oauth_connection
from bots.tasks.validate_zoom_oauth_connections_task import validate_zoom_oauth_connections
from bots.tests.zoom_log_capture import CaptureZoomLogBytes
from bots.zoom_oauth_connections_utils import ZoomOAuthConnectionRemovalFenced, _get_access_token
from bots.zoom_retention import (
    RECEIPT_RETENTION_DAYS,
    DatabaseVerificationError,
    ExpectedGrantMismatch,
    OperationConflict,
    ProviderOutcome,
    StorageVerificationError,
    _delete_and_verify_storage,
    _revoke_at_zoom,
    delete_expired_receipts,
    operation_result,
    process_bot_purge,
    process_connection_revoke,
    target_digest,
)


def expected_tuple(connection):
    """Synthetic immutable-grant fixture for the pre-lineage retention tests.

    These tests exercise token outcomes, not temporal/signed authority. Keep
    their fixture history explicitly legacy/incomplete; never upgrade it.
    """
    from bots.models import ZoomOAuthAuthorizationGrant, ZoomOAuthAuthorizationLineage, ZoomRemovalAuditKeyFingerprint

    grant = ZoomOAuthAuthorizationGrant.objects.filter(zoom_oauth_app=connection.zoom_oauth_app, authorization_generation=connection.authorization_generation).first()
    if grant is None:
        identity = hashlib.sha256(str(connection.authorization_generation).encode()).hexdigest()
        fingerprint = hashlib.sha256(("synthetic-key:" + str(connection.zoom_oauth_app_id)).encode()).hexdigest()
        ZoomRemovalAuditKeyFingerprint.objects.get_or_create(project=connection.zoom_oauth_app.project, zoom_oauth_app=connection.zoom_oauth_app, key_id="synthetic-test", defaults={"key_fingerprint": fingerprint})
        lineage = ZoomOAuthAuthorizationLineage.objects.create(project=connection.zoom_oauth_app.project, zoom_oauth_app=connection.zoom_oauth_app, identity_digest=identity, identity_audit_key_id="synthetic-test", identity_audit_key_fingerprint=fingerprint, latest_grant_sequence=1, has_prior_grant=True, history_complete=False)
        grant = ZoomOAuthAuthorizationGrant.objects.create(project=connection.zoom_oauth_app.project, zoom_oauth_app=connection.zoom_oauth_app, lineage=lineage, grant_sequence=1, live_connection=connection, connection_digest=hashlib.sha256(connection.object_id.encode()).hexdigest(), identity_digest=identity, identity_audit_key_id="synthetic-test", identity_audit_key_fingerprint=fingerprint, connection_audit_key_id="synthetic-test", connection_audit_key_fingerprint=fingerprint, authorization_generation=connection.authorization_generation, generation_started_at=timezone.now(), start_clock_health_id="synthetic-legacy-test", start_clock_continuous=False, legacy_history=True)
    return dict(zoom_oauth_app_binding=connection.zoom_oauth_app.deauthorization_binding_id, grant_binding_id=grant.binding_id, authorization_generation=grant.authorization_generation)


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
        self.runtime_absence_patch = patch("bots.bot_runtime_fence.bot_runtime_is_absent", return_value=True)
        self.runtime_absence = self.runtime_absence_patch.start()

    def tearDown(self):
        self.runtime_absence_patch.stop()
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

    def ambiguously_fence_connection(self, connection):
        with patch("bots.zoom_retention._revoke_at_zoom", return_value=ProviderOutcome(False, "revoke_transport_unknown")):
            return process_connection_revoke(
                project=self.project,
                operation_id=uuid.uuid4(),
                connection_object_id=connection.object_id,
                source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
                **expected_tuple(connection),
            )

    def revoke_payload(self, connection, operation_id=None, source=ZoomRemovalOperationSources.SKYTERRA_INITIATED, project=None):
        return {
            "project_id": (project or self.project).object_id,
            "operation_id": str(operation_id or uuid.uuid4()),
            "connection_id": connection.object_id,
            "source": source,
            **{key: str(value) for key, value in expected_tuple(connection).items()},
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

        with CaptureZoomLogBytes() as capture:
            result = self.post("/api/v1/zoom_retention/revoke", self.revoke_payload(connection, operation_id))

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["state"], ZoomRemovalOperationStates.REVOKED)
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())
        operation = ZoomRemovalOperation.objects.get(project=self.project, operation_id=operation_id)
        self.assertIsNone(operation.target_object_id)
        self.assertEqual(operation.storage_manifest, {})
        self.assertIsNone(operation.lease_token)
        self.assertIsNone(operation.lease_expires_at)
        self.assertIsNotNone(operation.completed_at)
        self.assertIsNotNone(operation.expires_at)
        self.assertEqual(
            operation.expires_at - operation.completed_at,
            timedelta(days=RECEIPT_RETENTION_DAYS),
        )
        self.assertEqual(
            operation.target_digest,
            target_digest(
                self.project,
                operation.operation_type,
                connection.object_id,
            ),
        )
        self.assertEqual(post.call_args_list[0].args[0], "https://zoom.us/oauth/token")
        self.assertEqual(post.call_args_list[1].args[0], "https://zoom.us/oauth/revoke")
        self.assertNotIn("?", post.call_args_list[1].args[0])
        receipt_readback = json.dumps(operation_result(operation), sort_keys=True)
        capture.assert_absent(
            self,
            refresh_token,
            access_token,
            connection.object_id,
            connection.user_id,
            connection.account_id,
        )
        for marker in (
            refresh_token,
            access_token,
            connection.object_id,
            connection.user_id,
            connection.account_id,
        ):
            self.assertNotIn(marker, result.content.decode() + receipt_readback)

    @patch("bots.zoom_retention.requests.post")
    def test_ambiguous_network_revoke_is_not_success_and_keeps_credentials(self, post):
        marker = "ambiguous-secret-never-log"
        connection = self.make_connection(refresh_token=marker)
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
        self.assertEqual(connection.get_credentials()["_zoom_retention_pending_revoke_access_token"], marker)
        self.assertEqual(connection.state, ZoomOAuthConnectionStates.REMOVING)
        self.assertNotIn(marker, result.content.decode() + stream.getvalue())

    @patch("bots.zoom_retention.requests.post")
    def test_explicit_already_revoked_is_terminal_but_unrecognized_4xx_is_retryable(self, post):
        terminal = self.make_connection(refresh_token="terminal-refresh")
        post.side_effect = [
            response(200, {"access_token": "terminal-access"}),
            response(400, {"code": 4741, "message": "token revoked"}),
        ]
        terminal_result = self.post("/api/v1/zoom_retention/revoke", self.revoke_payload(terminal))
        self.assertEqual(terminal_result.json()["state"], ZoomRemovalOperationStates.REVOKED)
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=terminal.pk).exists())

        retryable = self.make_connection(refresh_token="retryable-refresh")
        post.side_effect = [
            response(200, {"access_token": "retryable-access"}),
            response(400, {"error": "invalid_grant"}),
        ]
        retryable_result = self.post("/api/v1/zoom_retention/revoke", self.revoke_payload(retryable))
        self.assertEqual(retryable_result.json()["state"], ZoomRemovalOperationStates.REVOKE_UNKNOWN)
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=retryable.pk).exists())

    @patch("bots.zoom_retention.requests.post")
    def test_generic_project_caller_cannot_assert_zoom_deauthorization(self, post):
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
        self.assertEqual(result.status_code, 400)
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())
        self.assertTrue(ZoomMeetingToZoomOAuthConnectionMapping.objects.filter(pk=mapping.pk).exists())
        self.assertTrue(WebhookDeliveryAttempt.objects.filter(pk=delivery_attempt.pk).exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())
        generic_digest = target_digest(
            self.project,
            ZoomRemovalOperationTypes.REVOKE_CONNECTION,
            connection.object_id,
        )
        self.assertRegex(generic_digest, r"^[0-9a-f]{64}$")
        self.assertNotIn(connection.object_id, generic_digest)
        self.assertNotEqual(
            generic_digest,
            target_digest(
                self.project,
                ZoomRemovalOperationTypes.PURGE_BOT,
                connection.object_id,
            ),
        )
        post.assert_not_called()

    @patch("bots.zoom_retention.requests.post")
    def test_untrusted_deauthorization_cannot_upgrade_ambiguous_operation(self, post):
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
        self.assertEqual(second.status_code, 400)
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())
        operation = ZoomRemovalOperation.objects.get(operation_id=operation_id)
        self.assertEqual(operation.source, ZoomRemovalOperationSources.SKYTERRA_INITIATED)
        self.assertEqual(operation.state, ZoomRemovalOperationStates.REVOKE_UNKNOWN)
        post.assert_not_called()

    @patch("bots.zoom_retention.requests.post")
    def test_rate_limits_provider_errors_and_free_text_never_prove_revocation(self, post):
        cases = [
            (429, {"code": 4741, "message": "token revoked"}, "revoke_rate_limited"),
            (500, {"code": 4741, "message": "token expired"}, "revoke_provider_unavailable"),
            (503, {"message": "already revoked"}, "revoke_provider_unavailable"),
            (400, {"code": "4741", "message": "token revoked"}, "revoke_unrecognized_response"),
            (401, {"code": 4741, "message": "token revoked"}, "revoke_unrecognized_response"),
        ]
        for status_code, payload, failure_code in cases:
            with self.subTest(status_code=status_code, payload=payload):
                connection = self.make_connection()
                post.side_effect = [response(200, {"access_token": "exact-replay-token"}), response(status_code, payload)]
                outcome = _revoke_at_zoom(connection)
                self.assertFalse(outcome.terminal)
                self.assertEqual(outcome.failure_code, failure_code)
                self.assertTrue(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())

    @patch("bots.zoom_retention.requests.post")
    def test_refresh_rate_limit_provider_error_and_malformed_body_stay_unknown(self, post):
        malformed = response(200, {})
        malformed.json.side_effect = ValueError("malformed")
        cases = [
            response(429, {"code": 4741, "message": "token expired"}),
            response(503, {"code": 4741, "message": "already revoked"}),
            malformed,
        ]
        for provider_response in cases:
            with self.subTest(status_code=provider_response.status_code):
                connection = self.make_connection()
                post.side_effect = [provider_response]
                outcome = _revoke_at_zoom(connection)
                self.assertFalse(outcome.terminal)
                self.assertTrue(ZoomOAuthConnection.objects.filter(pk=connection.pk).exists())

    @patch("bots.zoom_retention.requests.post")
    def test_lost_revoke_success_replays_exact_encrypted_access_token(self, post):
        access_token = "lost-success-exact-token-never-log"
        connection = self.make_connection()
        operation_id = uuid.uuid4()
        post.side_effect = [response(200, {"access_token": access_token}), requests.Timeout("response lost")]

        first = process_connection_revoke(
            project=self.project,
            operation_id=operation_id,
            connection_object_id=connection.object_id,
            source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
            **expected_tuple(connection),
        )
        self.assertEqual(first.state, ZoomRemovalOperationStates.REVOKE_UNKNOWN)
        connection.refresh_from_db()
        self.assertEqual(connection.get_credentials()["_zoom_retention_pending_revoke_access_token"], access_token)

        post.reset_mock()
        post.side_effect = None
        post.return_value = response(400, {"code": 4741, "message": "token revoked"})
        second = process_connection_revoke(
            project=self.project,
            operation_id=operation_id,
            connection_object_id=connection.object_id,
            source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
            **expected_tuple(connection),
        )
        self.assertEqual(second.state, ZoomRemovalOperationStates.REVOKED)
        post.assert_called_once()
        self.assertEqual(post.call_args.kwargs["data"]["token"], access_token)

    @patch("bots.zoom_retention.requests.post")
    def test_lost_revoke_without_exact_terminal_proof_retains_replay_token(self, post):
        access_token = "unproved-exact-token-never-log"
        connection = self.make_connection()
        operation_id = uuid.uuid4()
        post.side_effect = [response(200, {"access_token": access_token}), requests.Timeout("response lost")]
        process_connection_revoke(
            project=self.project,
            operation_id=operation_id,
            connection_object_id=connection.object_id,
            source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
            **expected_tuple(connection),
        )

        post.reset_mock()
        post.side_effect = None
        post.return_value = response(400, {"error": "invalid_grant"})
        replay = process_connection_revoke(
            project=self.project,
            operation_id=operation_id,
            connection_object_id=connection.object_id,
            source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
            **expected_tuple(connection),
        )
        self.assertEqual(replay.state, ZoomRemovalOperationStates.REVOKE_UNKNOWN)
        connection.refresh_from_db()
        self.assertEqual(connection.get_credentials()["_zoom_retention_pending_revoke_access_token"], access_token)
        post.assert_called_once()

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

    @patch("bots.zoom_retention._delete_and_verify_storage", return_value=None)
    def test_failed_kubernetes_cleanup_keeps_fatal_bot_pending_then_converges_after_absence(self, storage):
        bot = self.make_bot(state=BotStates.FATAL_ERROR)
        bot.runtime_backend = "kubernetes"
        bot.runtime_launch_started_at = timezone.now()
        bot.runtime_launch_completed_at = timezone.now()
        bot.runtime_identifier = "provider-runtime-uid"
        bot.save()
        operation_id = uuid.uuid4()

        with patch("bots.bot_runtime_fence.bot_runtime_is_absent", return_value=False):
            first = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(first.state, ZoomRemovalOperationStates.PENDING_ACTIVE)
        self.assertEqual(first.failure_code, "runtime_absence_unproved")
        self.assertTrue(Bot.objects.filter(pk=bot.pk).exists())
        storage.assert_not_called()

        with patch("bots.bot_runtime_fence.bot_runtime_is_absent", return_value=True):
            second = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(second.state, ZoomRemovalOperationStates.PURGED)
        self.assertFalse(Bot.objects.filter(pk=bot.pk).exists())

    def test_celery_fatal_bot_without_runner_completion_has_no_absence_proof(self):
        bot = self.make_bot(state=BotStates.FATAL_ERROR)
        bot.removal_requested_at = timezone.now()
        bot.runtime_backend = "celery"
        bot.runtime_launch_started_at = timezone.now()
        bot.runtime_launch_completed_at = None
        bot.runtime_launch_in_progress = False
        bot.save()
        self.assertFalse(bot_runtime_is_absent(bot))

    def test_failed_kubernetes_delete_cannot_be_mistaken_for_runtime_absence(self):
        from kubernetes import client as kubernetes_client

        bot = self.make_bot(state=BotStates.FATAL_ERROR)
        bot.removal_requested_at = timezone.now()
        bot.runtime_backend = "kubernetes"
        bot.runtime_identifier = "matching-provider-uid"
        bot.runtime_launch_started_at = timezone.now()
        bot.runtime_launch_completed_at = timezone.now()
        bot.save()
        pod = Mock(metadata=Mock(uid=bot.runtime_identifier))
        api = Mock()
        api.read_namespaced_pod.return_value = pod
        api.delete_namespaced_pod.side_effect = kubernetes_client.ApiException(status=500)
        with (
            patch("kubernetes.config.load_incluster_config"),
            patch("kubernetes.client.CoreV1Api", return_value=api),
        ):
            self.assertFalse(bot_runtime_is_absent(bot))
        api.delete_namespaced_pod.assert_called_once()

    @patch("bots.zoom_retention._delete_and_verify_storage")
    def test_scheduled_launch_is_fenced_and_receipt_survives_response_loss(self, storage):
        bot = self.make_bot(state=BotStates.SCHEDULED)
        bot.join_at = timezone.now()
        bot.save()
        operation_id = uuid.uuid4()
        entered = threading.Event()
        release = threading.Event()
        worker_result = []

        def blocked_storage(_manifest):
            entered.set()
            release.wait(timeout=10)

        storage.side_effect = blocked_storage

        def purge_worker():
            close_old_connections()
            try:
                worker_result.append(
                    process_bot_purge(
                        project=Project.objects.get(pk=self.project.pk),
                        operation_id=operation_id,
                        bot_object_id=bot.object_id,
                    )
                )
            finally:
                close_old_connections()

        thread = threading.Thread(target=purge_worker)
        thread.start()
        self.assertTrue(entered.wait(timeout=10))
        bot.refresh_from_db()
        self.assertEqual(bot.runtime_absence_generation, bot.runtime_generation)
        self.assertIsNotNone(bot.runtime_absence_confirmed_at)
        with patch("bots.tasks.launch_scheduled_bot_task.launch_bot") as launch:
            launch_scheduled_bot(bot.pk, bot.join_at.isoformat())
        launch.assert_not_called()
        release.set()
        thread.join(timeout=20)
        self.assertFalse(thread.is_alive())
        self.assertEqual(worker_result[0].state, ZoomRemovalOperationStates.PURGED)

        replay = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
        self.assertEqual(replay.state, ZoomRemovalOperationStates.PURGED)
        self.assertEqual(replay.attempt_count, 1)

    def test_stale_connection_instance_cannot_restore_connected_state(self):
        connection = self.make_connection()
        stale = ZoomOAuthConnection.objects.get(pk=connection.pk)
        result = self.ambiguously_fence_connection(connection)
        self.assertEqual(result.state, ZoomRemovalOperationStates.REVOKE_UNKNOWN)

        stale.state = ZoomOAuthConnectionStates.CONNECTED
        with self.assertRaises((ValidationError, RecordModifiedError)):
            stale.save()
        connection.refresh_from_db()
        self.assertEqual(connection.state, ZoomOAuthConnectionStates.REMOVING)

    def test_stale_refresh_sync_and_validation_writers_cannot_resurrect_or_map(self):
        refresh_connection = self.make_connection()

        def fence_refresh(_connection):
            self.ambiguously_fence_connection(refresh_connection)
            return "stale-access"

        with patch("bots.tasks.refresh_zoom_oauth_connection_task._get_access_token", side_effect=fence_refresh):
            refresh_zoom_oauth_connection(refresh_connection.pk)
        refresh_connection.refresh_from_db()
        self.assertEqual(refresh_connection.state, ZoomOAuthConnectionStates.REMOVING)
        self.assertIsNone(refresh_connection.last_successful_token_refresh_at)

        sync_connection = self.make_connection()

        def fence_sync(_connection):
            self.ambiguously_fence_connection(sync_connection)
            return "stale-access"

        with (
            patch("bots.tasks.sync_zoom_oauth_connection_task._get_access_token", side_effect=fence_sync),
            patch("bots.tasks.sync_zoom_oauth_connection_task._get_zoom_meetings", return_value=[{"id": "987654321"}]) as get_meetings,
            patch("bots.tasks.sync_zoom_oauth_connection_task._get_zoom_personal_meeting_id", return_value="123456789") as get_personal_meeting,
        ):
            sync_zoom_oauth_connection(sync_connection.pk)
        sync_connection.refresh_from_db()
        self.assertEqual(sync_connection.state, ZoomOAuthConnectionStates.REMOVING)
        get_meetings.assert_not_called()
        get_personal_meeting.assert_not_called()
        self.assertFalse(ZoomMeetingToZoomOAuthConnectionMapping.objects.filter(zoom_oauth_connection=sync_connection).exists())

        validation_connection = self.make_connection()
        validation_connection.state = ZoomOAuthConnectionStates.DISCONNECTED
        validation_connection.connection_failure_data = {"error": "Invalid client_id or client_secret"}
        validation_connection.save()

        def fence_validation(_connection):
            self.ambiguously_fence_connection(validation_connection)
            return "stale-access"

        with patch("bots.tasks.validate_zoom_oauth_connections_task._get_access_token", side_effect=fence_validation):
            validate_zoom_oauth_connections(self.zoom_app.pk)
        validation_connection.refresh_from_db()
        self.assertEqual(validation_connection.state, ZoomOAuthConnectionStates.REMOVING)

    @patch("bots.zoom_oauth_connections_utils.requests.post")
    def test_token_rotation_cannot_write_after_removal_fence(self, post):
        connection = self.make_connection(refresh_token="original-refresh")
        provider_response = response(200, {})
        provider_response.raise_for_status.return_value = None

        def fence_before_rotation():
            self.ambiguously_fence_connection(connection)
            return {"access_token": "stale-access", "refresh_token": "rotated-refresh"}

        provider_response.json.side_effect = fence_before_rotation
        post.return_value = provider_response
        with self.assertRaises(ZoomOAuthConnectionRemovalFenced):
            _get_access_token(connection)
        connection.refresh_from_db()
        self.assertEqual(connection.state, ZoomOAuthConnectionStates.REMOVING)
        self.assertEqual(connection.get_credentials()["refresh_token"], "original-refresh")

    def test_removal_dedupe_is_generation_scoped_after_fresh_reconnection(self):
        old_connection = self.make_connection()
        operation_id = uuid.uuid4()
        with patch("bots.zoom_retention._revoke_at_zoom", return_value=ProviderOutcome(False, "revoke_transport_unknown")):
            first = process_connection_revoke(
                project=self.project,
                operation_id=operation_id,
                connection_object_id=old_connection.object_id,
                source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
                **expected_tuple(old_connection),
            )
        self.assertEqual(first.state, ZoomRemovalOperationStates.REVOKE_UNKNOWN)
        old_generation = old_connection.authorization_generation
        with self.assertRaises(OperationConflict) as duplicate_conflict:
            process_connection_revoke(
                project=self.project,
                operation_id=uuid.uuid4(),
                connection_object_id=old_connection.object_id,
                source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
                **expected_tuple(old_connection),
            )
        self.assertEqual(duplicate_conflict.exception.canonical_operation_id, operation_id)

        # Synthetic fixture replacement for this legacy dedupe test; the
        # exact-capture callback is exercised by the expected-grant tests.
        with transaction.atomic():
            grant = old_connection.authorization_grant
            grant.generation_ended_at = timezone.now()
            grant.end_clock_health_id = "synthetic-legacy-test"
            grant.end_clock_error_ms = 0
            grant.end_clock_continuous = False
            grant.live_connection = None
            grant.save()
            replacement = ZoomOAuthConnection.objects.select_for_update().get(pk=old_connection.pk)
            replacement.state = ZoomOAuthConnectionStates.CONNECTED
            replacement.replace_authorization_credentials({"refresh_token": "replacement-refresh"})
        expected_tuple(replacement)
        self.assertEqual(replacement.pk, old_connection.pk)
        self.assertNotEqual(replacement.authorization_generation, old_generation)
        with self.assertRaises(ExpectedGrantMismatch):
            process_connection_revoke(
                project=self.project,
                operation_id=operation_id,
                connection_object_id=replacement.object_id,
                source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
                **expected_tuple(replacement),
            )
        replacement.refresh_from_db()
        self.assertEqual(replacement.state, ZoomOAuthConnectionStates.CONNECTED)
        self.assertEqual(replacement.get_credentials()["refresh_token"], "replacement-refresh")

        fresh_operation_id = uuid.uuid4()
        with patch("bots.zoom_retention._revoke_at_zoom", return_value=ProviderOutcome(True)):
            fresh_removal = process_connection_revoke(
                project=self.project,
                operation_id=fresh_operation_id,
                connection_object_id=replacement.object_id,
                source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
                **expected_tuple(replacement),
            )
        self.assertEqual(fresh_removal.state, ZoomRemovalOperationStates.REVOKED)
        self.assertEqual(fresh_removal.target_generation, replacement.authorization_generation)
        self.assertNotEqual(fresh_removal.target_generation, first.target_generation)
        self.assertEqual(fresh_removal.target_digest, first.target_digest)
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=replacement.pk).exists())
        first.refresh_from_db()
        self.assertEqual(first.state, ZoomRemovalOperationStates.REVOKE_UNKNOWN)

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
        self.assertEqual(
            receipt.expires_at - receipt.completed_at,
            timedelta(days=RECEIPT_RETENTION_DAYS),
        )

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

    def test_expired_lease_reclaimer_fences_old_worker_after_over_300_seconds(self):
        bot = self.make_bot()
        operation_id = uuid.uuid4()
        entered = threading.Event()
        release = threading.Event()
        calls = []
        calls_lock = threading.Lock()
        old_results = []

        def storage_step(_manifest):
            with calls_lock:
                calls.append(threading.get_ident())
                call_number = len(calls)
            if call_number == 1:
                entered.set()
                release.wait(timeout=20)

        def old_worker():
            close_old_connections()
            try:
                old_results.append(
                    process_bot_purge(
                        project=Project.objects.get(pk=self.project.pk),
                        operation_id=operation_id,
                        bot_object_id=bot.object_id,
                    )
                )
            finally:
                close_old_connections()

        with patch("bots.zoom_retention._delete_and_verify_storage", side_effect=storage_step):
            thread = threading.Thread(target=old_worker)
            thread.start()
            self.assertTrue(entered.wait(timeout=10))
            ZoomRemovalOperation.objects.filter(project=self.project, operation_id=operation_id).update(lease_expires_at=timezone.now() - timedelta(seconds=1))
            reclaimed = process_bot_purge(project=self.project, operation_id=operation_id, bot_object_id=bot.object_id)
            self.assertEqual(reclaimed.state, ZoomRemovalOperationStates.PURGED)
            release.set()
            thread.join(timeout=20)

        self.assertFalse(thread.is_alive())
        self.assertEqual(old_results[0].state, ZoomRemovalOperationStates.PURGED)
        receipt = ZoomRemovalOperation.objects.get(operation_id=operation_id)
        self.assertEqual(receipt.attempt_count, 2)
        self.assertGreaterEqual(len(calls), 3)

    def test_completed_receipt_expires_after_bounded_window(self):
        bot = self.make_bot()
        with patch("bots.zoom_retention._delete_and_verify_storage", return_value=None):
            operation = process_bot_purge(project=self.project, operation_id=uuid.uuid4(), bot_object_id=bot.object_id)
        self.assertEqual(
            operation.expires_at - operation.completed_at,
            timedelta(days=RECEIPT_RETENTION_DAYS),
        )
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
