import logging
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone

from accounts.models import Organization
from attendee.logging import log_bounded_exception
from bots.external_callback_utils import get_zoom_tokens
from bots.management.commands.run_scheduler import Command
from bots.models import (
    Bot,
    Project,
    WebhookDeliveryAttempt,
    WebhookSecret,
    WebhookSubscription,
    WebhookTriggerTypes,
    ZoomOAuthApp,
    ZoomOAuthConnection,
)
from bots.tasks.deliver_webhook_task import (
    MAX_WEBHOOK_DELIVERY_ATTEMPTS,
    deliver_webhook,
)
from bots.tasks.refresh_zoom_oauth_connection_task import (
    refresh_zoom_oauth_connection,
)
from bots.tasks.sync_calendar_task import sync_bot_with_calendar_event
from bots.tasks.sync_zoom_oauth_connection_task import sync_zoom_oauth_connection
from bots.tasks.validate_zoom_oauth_connections_task import (
    validate_zoom_oauth_connections,
)
from bots.tests.zoom_log_capture import (
    CaptureConfiguredZoomLogBytes,
    CaptureZoomLogBytes,
)
from bots.zoom_oauth_connections_api_utils import create_zoom_oauth_connection
from bots.zoom_oauth_connections_utils import (
    ZoomAPIAuthenticationError,
    ZoomAPIError,
    ZoomOAuthConnectionRemovalFenced,
)


class ZoomLogBoundaryUnitTests(SimpleTestCase):
    def test_json_access_log_filter_scrubs_query_structured_request_and_traceback(self):
        object_id = "zoc_ACCESS_LOG_CANARY_9876"
        query_secret = "authorization-code-access-canary"
        request_body = "request-body-access-canary"
        header_token = "bearer-header-access-canary"
        assertion = "eyJhbGciOiJFZERTQSJ9.eyJ6b29tX2V2ZW50X2lkIjoiY2FuYXJ5In0.signatureSegmentAccessCanary"
        path = f"/api/v1/zoom_retention/operations/{object_id}?code={query_secret}"
        try:
            raise RuntimeError("provider-traceback-access-canary")
        except RuntimeError:
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            "django.request",
            logging.ERROR,
            __file__,
            1,
            "Zoom Bad Request: %s assertion=%s",
            (path, assertion),
            exc_info,
        )
        record.status_code = 400
        record.request = SimpleNamespace(path=path, body=request_body)
        record.headers = {"Authorization": f"Bearer {header_token}"}
        record.request_data = {"assertion": assertion}

        with CaptureZoomLogBytes() as capture:
            logging.getLogger("django.request").handle(record)

        capture.assert_absent(
            self,
            object_id,
            query_secret,
            request_body,
            header_token,
            assertion,
            "signatureSegmentAccessCanary",
            "provider-traceback-access-canary",
        )
        self.assertIn(b"[redacted-id]", capture.bytes)
        self.assertIn(b"[redacted-query]", capture.bytes)
        self.assertIn(b"[redacted-assertion]", capture.bytes)

    def test_bounded_exception_mapper_never_renders_provider_exception(self):
        provider_text = "provider-json-text-exception-canary"
        prepared_url = "https://api.zoom.us/v2/users/user-canary?token=token-canary"
        response = Mock(status_code=503, text=provider_text)
        response.request = Mock(url=prepared_url, headers={"Authorization": "Bearer secret"})
        error = requests.HTTPError(provider_text, response=response)

        with CaptureZoomLogBytes() as capture:
            log_bounded_exception(
                logging.getLogger("bots.zoom_logging_boundary_test"),
                "zoom_test_failed",
                "provider_request_failed",
                error,
            )

        capture.assert_absent(self, provider_text, prepared_url, "Bearer secret", "token-canary")
        self.assertIn(b"exception_class=HTTPError", capture.bytes)
        self.assertIn(b"http_status_class=5xx", capture.bytes)

    def test_calendar_and_bot_adapter_call_sites_emit_no_zoom_identifiers(self):
        old_url = "https://zoom.us/j/111122223333?pwd=old-url-canary"
        new_url = "https://zoom.us/j/999988887777?pwd=new-url-canary"
        bot_id = "bot_ADAPTER_LOG_CANARY_9876"
        calendar_event_id = "calendar-meeting-event-log-canary"
        calendar_bot = SimpleNamespace(
            object_id=bot_id,
            meeting_url=old_url,
            join_at=1,
        )
        calendar_event = SimpleNamespace(
            is_deleted=False,
            meeting_url=new_url,
            start_time=1,
            platform_uuid=calendar_event_id,
        )

        # Exercise the actual call sites without starting browser or SDK I/O.
        from bots.web_bot_adapter.web_bot_adapter import WebBotAdapter
        from bots.zoom_bot_adapter.zoom_bot_adapter import ZoomBotAdapter

        web_adapter = SimpleNamespace(
            meeting_url=old_url,
            init_driver=lambda: None,
            attempt_to_join_meeting=lambda: None,
            after_bot_joined_meeting=lambda: None,
            subclass_specific_after_bot_joined_meeting=lambda: None,
        )
        native_user_id = "zoom-native-participant-user-id-canary"
        native_adapter = SimpleNamespace(
            update_only_one_participant_in_meeting_at=lambda: None,
            get_participant=lambda _user_id: None,
            send_participant_event=lambda _user_id, event_type: None,
            request_permission_to_record_if_joined_user_is_host=lambda _user_id: None,
        )

        with (
            CaptureZoomLogBytes() as capture,
            patch(
                "bots.tasks.sync_calendar_task.patch_bot",
                return_value=(calendar_bot, None),
            ),
        ):
            sync_bot_with_calendar_event(calendar_bot, calendar_event)
            WebBotAdapter.repeatedly_attempt_to_join_meeting(web_adapter)
            ZoomBotAdapter.on_user_join_callback(
                native_adapter,
                [native_user_id],
                None,
            )
            ZoomBotAdapter.on_user_left_callback(
                native_adapter,
                [native_user_id],
                None,
            )

        capture.assert_absent(
            self,
            old_url,
            new_url,
            "111122223333",
            "999988887777",
            bot_id,
            calendar_event_id,
            native_user_id,
        )
        self.assertIn(b"calendar_sync_bot_patch_started", capture.bytes)
        self.assertIn(b"zoom_web_join_started", capture.bytes)
        self.assertIn(b"zoom_native_participant_joined", capture.bytes)


@override_settings(
    ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE=False,
    REQUIRE_PUBLIC_WEBHOOK_URLS=False,
    LOG_BOT_STATE_CHANGES=False,
)
class ZoomLogBoundaryFlowTests(TransactionTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Logging Boundary Org")
        self.project = Project.objects.create(
            organization=self.organization,
            name="Logging Boundary Project",
        )
        self.client_id = "zoom-client-id-log-canary"
        self.client_secret = "zoom-client-secret-log-canary"
        self.app = ZoomOAuthApp.objects.create(
            project=self.project,
            object_id="zoa_LOG_APP_CANARY_9876",
            client_id=self.client_id,
        )
        self.app.set_credentials({"client_secret": self.client_secret})
        self.authorization_code = "authorization-code-log-canary"
        self.redirect_uri = "https://client-agent.test/callback/redirect-log-canary"
        self.access_token = "access-token-log-canary"
        self.refresh_token = "refresh-token-log-canary"
        self.user_id = "zoom-user-id-log-canary"
        self.account_id = "zoom-account-id-log-canary"

    def _oauth_payload(self):
        return {
            "zoom_oauth_app_id": self.app.object_id,
            "authorization_code": self.authorization_code,
            "redirect_uri": self.redirect_uri,
            "is_local_recording_token_supported": True,
        }

    def _oauth_tokens(self):
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "scope": ("user:read:user user:read:zak meeting:read:list_meetings meeting:read:local_recording_token"),
        }

    def test_successful_oauth_and_sync_emit_no_identifier_or_secret_canaries(self):
        provider_user = {
            "id": self.user_id,
            "account_id": self.account_id,
            "status": "active",
        }
        with (
            CaptureZoomLogBytes() as callback_logs,
            patch(
                "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens",
                return_value=self._oauth_tokens(),
            ),
            patch(
                "bots.zoom_oauth_connections_api_utils._get_user_info",
                return_value=provider_user,
            ),
        ):
            connection, error = create_zoom_oauth_connection(
                self._oauth_payload(),
                self.project,
            )

        self.assertIsNone(error)
        self.assertIsNotNone(connection)
        callback_logs.assert_absent(
            self,
            self.authorization_code,
            self.redirect_uri,
            self.access_token,
            self.refresh_token,
            self.client_id,
            self.client_secret,
            self.user_id,
            self.account_id,
            self.app.object_id,
            connection.object_id,
        )

        meeting_id = "987654321012345678"
        meeting_uuid = "meeting-uuid-log-canary"
        meeting_url = "https://zoom.us/j/987654321012345678?pwd=meeting-url-log-canary"
        pmi = "112233445566778899"
        with (
            CaptureZoomLogBytes() as worker_logs,
            patch(
                "bots.tasks.sync_zoom_oauth_connection_task._get_access_token",
                return_value=self.access_token,
            ),
            patch(
                "bots.tasks.sync_zoom_oauth_connection_task._get_zoom_meetings",
                return_value=[{"id": meeting_id, "uuid": meeting_uuid, "join_url": meeting_url}],
            ),
            patch(
                "bots.tasks.sync_zoom_oauth_connection_task._get_zoom_personal_meeting_id",
                return_value=pmi,
            ),
        ):
            sync_zoom_oauth_connection(connection.pk)

        worker_logs.assert_absent(
            self,
            self.access_token,
            self.refresh_token,
            self.user_id,
            self.account_id,
            self.app.object_id,
            connection.object_id,
            meeting_id,
            meeting_uuid,
            meeting_url,
            pmi,
        )
        self.assertIn(b"meeting_count=1", worker_logs.bytes)

    def test_configured_django_and_gunicorn_access_pipeline_redacts_raw_bytes(self):
        query_secret = "configured-access-query-secret-canary"
        request_body = "configured-access-request-body-canary"
        header_token = "configured-access-bearer-token-canary"
        path = f"/external_webhooks/zoom/oauth_apps/{self.app.object_id}?code={query_secret}"

        with CaptureConfiguredZoomLogBytes() as capture:
            response = self.client.get(path)
            logging.getLogger("gunicorn.access").warning(
                "Zoom access GET %s status=400",
                path,
                extra={
                    "request": SimpleNamespace(path=path, body=request_body),
                    "headers": {"Authorization": f"Bearer {header_token}"},
                },
            )

        self.assertEqual(response.status_code, 405)
        capture.assert_absent(
            self,
            self.app.object_id,
            query_secret,
            request_body,
            header_token,
        )
        self.assertIn(b"[redacted-id]", capture.bytes)
        self.assertIn(b"[redacted-query]", capture.bytes)

    def test_celery_trace_refresh_and_validate_failures_only_render_fixed_codes(self):
        connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.app,
            object_id="zoc_CELERY_TRACE_CANARY_9876",
            user_id=self.user_id,
            account_id=self.account_id,
        )
        connection.set_credentials({"refresh_token": self.refresh_token})
        transport_marker = "refresh-provider-transport-body-canary"

        with (
            CaptureConfiguredZoomLogBytes() as transport_logs,
            patch.object(
                refresh_zoom_oauth_connection,
                "max_retries",
                0,
            ),
            patch(
                "bots.tasks.refresh_zoom_oauth_connection_task._get_access_token",
                side_effect=RuntimeError(transport_marker),
            ),
        ):
            transport_result = refresh_zoom_oauth_connection.apply(
                args=(connection.pk,),
                throw=False,
            )

        self.assertTrue(transport_result.failed())
        self.assertEqual(str(transport_result.result), "zoom_oauth_refresh_failed")
        transport_logs.assert_absent(
            self,
            transport_marker,
            connection.object_id,
            self.user_id,
            self.account_id,
            self.refresh_token,
        )
        self.assertIn(b"zoom_oauth_refresh_failed", transport_logs.bytes)
        self.assertIn(
            b"Task bots.tasks.refresh_zoom_oauth_connection_task.refresh_zoom_oauth_connection",
            transport_logs.bytes,
        )

        auth_marker = "refresh-provider-auth-body-canary"
        webhook_marker = "refresh-auth-webhook-body-canary"
        with (
            CaptureConfiguredZoomLogBytes() as auth_logs,
            patch.object(
                refresh_zoom_oauth_connection,
                "max_retries",
                0,
            ),
            patch(
                "bots.tasks.refresh_zoom_oauth_connection_task._get_access_token",
                side_effect=ZoomAPIAuthenticationError(auth_marker),
            ),
            patch(
                "bots.zoom_oauth_connections_utils.trigger_webhook",
                side_effect=RuntimeError(webhook_marker),
            ),
        ):
            auth_result = refresh_zoom_oauth_connection.apply(
                args=(connection.pk,),
                throw=False,
            )

        self.assertTrue(auth_result.failed())
        self.assertEqual(str(auth_result.result), "zoom_auth_state_webhook_failed")
        auth_logs.assert_absent(
            self,
            auth_marker,
            webhook_marker,
            connection.object_id,
            self.user_id,
            self.account_id,
            self.refresh_token,
        )
        self.assertIn(b"zoom_auth_state_webhook_failed", auth_logs.bytes)
        self.assertIn(
            b"Task bots.tasks.refresh_zoom_oauth_connection_task.refresh_zoom_oauth_connection",
            auth_logs.bytes,
        )

        validate_marker = "validate-database-provider-body-canary"
        with (
            CaptureConfiguredZoomLogBytes() as validate_logs,
            patch.object(
                validate_zoom_oauth_connections,
                "max_retries",
                0,
            ),
            patch(
                "bots.tasks.validate_zoom_oauth_connections_task.ZoomOAuthApp.objects.get",
                side_effect=RuntimeError(validate_marker),
            ),
        ):
            validate_result = validate_zoom_oauth_connections.apply(
                args=(self.app.pk,),
                throw=False,
            )

        self.assertTrue(validate_result.failed())
        self.assertEqual(str(validate_result.result), "zoom_oauth_validation_failed")
        validate_logs.assert_absent(
            self,
            validate_marker,
            self.app.object_id,
            self.client_id,
            self.client_secret,
        )
        self.assertIn(b"zoom_oauth_validation_failed", validate_logs.bytes)
        self.assertIn(
            b"Task bots.tasks.validate_zoom_oauth_connections_task.validate_zoom_oauth_connections",
            validate_logs.bytes,
        )

    def _assert_celery_status_write_failure_is_bounded(self, task, operation):
        connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.app,
            object_id="zoc_STATUS_WRITE_CANARY_9876",
            user_id=self.user_id,
            account_id=self.account_id,
        )
        provider_marker = f"{operation}-original-provider-body-canary"
        status_marker = f"{operation}-status-write-database-body-canary"
        module = f"bots.tasks.{operation}_zoom_oauth_connection_task"
        failure_code = f"zoom_oauth_{operation}_failed"

        # Both exception paths must cross Celery's configured trace handler.
        # A removal fence still ends the task; an ordinary write failure must
        # reach the fixed retryable error instead of leaking its own text.
        for status_error in (
            RuntimeError(status_marker),
            ZoomOAuthConnectionRemovalFenced(status_marker),
        ):
            with self.subTest(status_error=type(status_error).__name__):
                with (
                    CaptureConfiguredZoomLogBytes() as capture,
                    patch.object(task, "max_retries", 0),
                    patch(
                        f"{module}._get_access_token",
                        side_effect=RuntimeError(provider_marker),
                    ),
                    patch(
                        f"{module}.update_zoom_oauth_connection_if_writable",
                        side_effect=status_error,
                    ) as update_status,
                ):
                    result = task.apply(args=(connection.pk,), throw=False)

                update_status.assert_called_once()
                capture.assert_absent(
                    self,
                    provider_marker,
                    status_marker,
                    connection.object_id,
                    self.user_id,
                    self.account_id,
                )
                self.assertIn(f"Task {module}.".encode(), capture.bytes)
                if isinstance(status_error, ZoomOAuthConnectionRemovalFenced):
                    self.assertTrue(result.successful())
                    self.assertIsNone(result.result)
                else:
                    self.assertTrue(result.failed())
                    self.assertIsInstance(result.result, ZoomAPIError)
                    self.assertEqual(str(result.result), failure_code)
                    self.assertIn(failure_code.encode(), capture.bytes)

    def test_celery_refresh_status_write_failure_only_renders_fixed_code(self):
        self._assert_celery_status_write_failure_is_bounded(refresh_zoom_oauth_connection, "refresh")

    def test_celery_sync_status_write_failure_only_renders_fixed_code(self):
        self._assert_celery_status_write_failure_is_bounded(sync_zoom_oauth_connection, "sync")

    def test_external_zoom_token_callback_success_and_failure_logs_are_raw_free(self):
        meeting_url = "https://zoom.us/j/445566778899?pwd=callback-meeting-url-canary"
        callback_url = "https://client-agent.test/zoom-tokens/callback-url-canary"
        bot = Bot.objects.create(
            project=self.project,
            object_id="bot_CALLBACK_LOG_CANARY_9876",
            meeting_url=meeting_url,
            settings={"callback_settings": {"zoom_tokens_url": callback_url}},
        )
        onbehalf_token = "onbehalf-token-log-canary"
        join_token = "join-token-log-canary"
        local_token = "local-recording-token-log-canary"
        success = Mock(status_code=200)
        success.json.return_value = {
            "zak_token": "zak-token-log-canary",
            "join_token": join_token,
            "app_privilege_token": local_token,
            "onbehalf_token": onbehalf_token,
        }

        with (
            CaptureZoomLogBytes() as success_logs,
            patch(
                "bots.external_callback_utils.requests.post",
                return_value=success,
            ),
        ):
            tokens = get_zoom_tokens(bot)
        self.assertEqual(tokens["onbehalf_token"], onbehalf_token)
        success_logs.assert_absent(
            self,
            bot.object_id,
            meeting_url,
            callback_url,
            join_token,
            local_token,
            onbehalf_token,
            "zak-token-log-canary",
        )
        self.assertIn(b"external_callback_completed", success_logs.bytes)

        provider_body = '{"error":"provider-error-json-log-canary"}'
        failed = Mock(status_code=502, text=provider_body)
        with (
            CaptureZoomLogBytes() as failure_logs,
            patch(
                "bots.external_callback_utils.requests.post",
                return_value=failed,
            ),
        ):
            failed_tokens = get_zoom_tokens(bot)
        self.assertTrue(all(value is None for value in failed_tokens.values()))
        failure_logs.assert_absent(
            self,
            provider_body,
            "provider-error-json-log-canary",
            bot.object_id,
            meeting_url,
            callback_url,
        )
        self.assertIn(b"code=http_error", failure_logs.bytes)
        self.assertIn(b"http_status_class=5xx", failure_logs.bytes)

    def test_scheduler_logs_no_connection_object_id(self):
        connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.app,
            object_id="zoc_SCHEDULER_LOG_CANARY_9876",
            user_id=self.user_id,
            account_id=self.account_id,
            is_local_recording_token_supported=True,
            sync_task_enqueued_at=timezone.now() - timezone.timedelta(days=8),
            token_refresh_task_enqueued_at=timezone.now() - timezone.timedelta(days=31),
        )
        command = Command()
        with CaptureZoomLogBytes() as capture, patch("bots.management.commands.run_scheduler.enqueue_sync_zoom_oauth_connection_task"), patch("bots.management.commands.run_scheduler.enqueue_refresh_zoom_oauth_connection_task"):
            command._run_periodic_zoom_oauth_connection_syncs()
            command._run_periodic_zoom_oauth_connection_token_refreshs()

        capture.assert_absent(
            self,
            connection.object_id,
            self.user_id,
            self.account_id,
            self.app.object_id,
        )
        self.assertIn(b"zoom_oauth_sync_enqueued", capture.bytes)
        self.assertIn(b"zoom_oauth_refresh_enqueued", capture.bytes)

    def test_zoom_state_webhook_worker_never_logs_payload_url_or_exception_text(self):
        connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.app,
            object_id="zoc_DELIVERY_LOG_CANARY_9876",
            user_id=self.user_id,
            account_id=self.account_id,
        )
        callback_url = "https://client-agent.test/webhook?token=webhook-url-token-log-canary"
        subscription = WebhookSubscription.objects.create(
            project=self.project,
            url=callback_url,
            triggers=[WebhookTriggerTypes.ZOOM_OAUTH_CONNECTION_STATE_CHANGE],
        )
        WebhookSecret.objects.create(project=self.project)
        payload_marker = "zoom-state-webhook-payload-log-canary"
        provider_error = "webhook-provider-exception-log-canary"
        delivery = WebhookDeliveryAttempt.objects.create(
            webhook_subscription=subscription,
            webhook_trigger_type=WebhookTriggerTypes.ZOOM_OAUTH_CONNECTION_STATE_CHANGE,
            idempotency_key="35353535-3535-4353-8353-353535353535",
            zoom_oauth_connection=connection,
            payload={"marker": payload_marker},
            attempt_count=MAX_WEBHOOK_DELIVERY_ATTEMPTS - 1,
        )

        with (
            CaptureZoomLogBytes() as capture,
            patch(
                "bots.tasks.deliver_webhook_task.requests.post",
                side_effect=requests.Timeout(provider_error),
            ),
        ):
            deliver_webhook(delivery.pk)

        capture.assert_absent(
            self,
            callback_url,
            "webhook-url-token-log-canary",
            payload_marker,
            provider_error,
            connection.object_id,
            self.user_id,
            self.account_id,
        )
        self.assertIn(b"code=transport_error", capture.bytes)
        self.assertIn(b"code=attempts_exhausted", capture.bytes)
