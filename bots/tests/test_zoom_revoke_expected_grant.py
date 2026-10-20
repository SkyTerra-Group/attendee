"""Current-grant revoke admission and captured-token reconnect interleavings."""

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import Mock, patch

import requests
from django.db import close_old_connections
from django.test import TransactionTestCase, override_settings

from bots import zoom_retention as service
from bots.models import ZoomOAuthConnection, ZoomRemovalOperation
from bots.tests import test_zoom_deauthorization as fixture


def response(code, body):
    result = Mock(status_code=code)
    result.json.return_value = body
    return result


@override_settings(**fixture.ZoomSignedDeauthorizationTests._overridden_settings)
class ExpectedGrantRevokeTests(TransactionTestCase):
    setUp = fixture.ZoomSignedDeauthorizationTests.setUp
    tearDown = fixture.ZoomSignedDeauthorizationTests.tearDown
    activate_audit_registry = fixture.ZoomSignedDeauthorizationTests.activate_audit_registry
    add_clock_sample = fixture.ZoomSignedDeauthorizationTests.add_clock_sample
    reconnect = fixture.ZoomSignedDeauthorizationTests._deferred_reconnect

    def payload(self, **changes):
        value = dict(project_id=self.project.object_id, operation_id=str(uuid.uuid4()), connection_id=self.connection.object_id, source="skyterra_initiated", zoom_oauth_app_binding=str(self.app_binding), grant_binding_id=str(self.grant.binding_id), authorization_generation=str(self.grant.authorization_generation))
        value.update(changes)
        return value

    def post(self, payload):
        return self.client.post("/api/v1/zoom_retention/revoke", data=json.dumps(payload), content_type="application/json", HTTP_AUTHORIZATION="Token " + self.api_key)

    def call(self, payload):
        value = dict(payload)
        value.pop("project_id")
        value["operation_id"] = uuid.UUID(value["operation_id"])
        value["connection_object_id"] = value.pop("connection_id")
        return service.process_connection_revoke(project=self.project, **value)

    def assert_replacement(self, replacement):
        replacement.refresh_from_db()
        self.assertEqual(replacement.state, 1)
        self.assertNotEqual(replacement.authorization_generation, self.grant.authorization_generation)
        self.assertEqual(replacement.get_credentials(), {"refresh_token": "recovery-refresh-test"})

    def test_missing_or_malformed_each_tuple_field_has_zero_effects(self):
        for field in ("zoom_oauth_app_binding", "grant_binding_id", "authorization_generation"):
            for value in (None, "invalid"):
                with self.subTest(field=field, value=value), patch("bots.zoom_retention.requests.post") as remote:
                    payload = self.payload(**{field: value})
                    result = self.post(payload)
                    self.assertEqual(result.status_code, 400)
                    remote.assert_not_called()
                    self.assertEqual(ZoomRemovalOperation.objects.count(), 0)
                    self.connection.refresh_from_db()
                    self.assertEqual(self.connection.state, 1)

    def test_internal_caller_missing_tuple_has_zero_effects(self):
        with patch("bots.zoom_retention.requests.post") as remote:
            with self.assertRaises(service.ExpectedGrantMismatch):
                service.process_connection_revoke(project=self.project, operation_id=uuid.uuid4(), connection_object_id=self.connection.object_id, source="skyterra_initiated")
            remote.assert_not_called()
        self.assertEqual(ZoomRemovalOperation.objects.count(), 0)

    def test_unauthenticated_request_has_zero_effects(self):
        with patch("bots.zoom_retention.requests.post") as remote:
            result = self.client.post("/api/v1/zoom_retention/revoke", data=json.dumps(self.payload()), content_type="application/json")
            self.assertIn(result.status_code, (401, 403))
            remote.assert_not_called()
        self.assertEqual(ZoomRemovalOperation.objects.count(), 0)

    def test_wrong_each_tuple_field_has_zero_effects(self):
        for field in ("zoom_oauth_app_binding", "grant_binding_id", "authorization_generation"):
            with self.subTest(field=field), patch("bots.zoom_retention.requests.post") as remote:
                result = self.post(self.payload(**{field: str(uuid.uuid4())}))
                self.assertEqual(result.status_code, 409)
                remote.assert_not_called()
                self.assertEqual(ZoomRemovalOperation.objects.count(), 0)
                self.connection.refresh_from_db()
                self.assertEqual(self.connection.state, 1)

    def test_cross_project_tuple_and_target_have_zero_effects(self):
        with patch("bots.zoom_retention.requests.post") as remote:
            payload = self.payload(project_id=self.other_project.object_id)
            result = self.client.post("/api/v1/zoom_retention/revoke", data=json.dumps(payload), content_type="application/json", HTTP_AUTHORIZATION="Token " + self.other_api_key)
            self.assertEqual(result.status_code, 404)
            remote.assert_not_called()
            self.assertEqual(ZoomRemovalOperation.objects.count(), 0)

    def test_same_tuple_terminal_retry_and_independent_get(self):
        payload = self.payload()
        with patch("bots.zoom_retention.requests.post", side_effect=[response(200, {"access_token": "access-A", "refresh_token": "refresh-A2"}), response(200, {"status": "success"})]) as remote:
            first = self.post(payload)
            self.assertEqual(first.status_code, 200, first.content)
            self.assertEqual(first.json()["terminal_basis"], "provider_revoke")
            self.assertEqual(remote.call_args.kwargs["data"], {"token": "access-A"})
        with patch("bots.zoom_retention.requests.post") as remote:
            again = self.post(payload)
            self.assertEqual(again.status_code, 200, again.content)
            self.assertEqual(again.json(), first.json())
            remote.assert_not_called()
        readback = self.client.get("/api/v1/zoom_retention/operations/" + first.json()["operation_id"], HTTP_AUTHORIZATION="Token " + self.api_key)
        self.assertEqual(readback.status_code, 200, readback.content)
        self.assertEqual(readback.json(), first.json())

    def test_replacement_before_admission_refuses_stale_tuple(self):
        payload = self.payload()
        replacement, error = self.reconnect()
        self.assertIsNone(error)
        with patch("bots.zoom_retention.requests.post") as remote:
            result = self.post(payload)
            self.assertEqual(result.status_code, 409, result.content)
            remote.assert_not_called()
        self.assertEqual(ZoomRemovalOperation.objects.count(), 0)
        self.assert_replacement(replacement)

    def test_operation_id_cannot_adopt_replacement_tuple(self):
        payload = self.payload()
        with patch("bots.zoom_retention._revoke_at_zoom", return_value=service.ProviderOutcome(False, "revoke_transport_unknown")):
            self.call(payload)
        replacement, error = self.reconnect()
        self.assertIsNone(error)
        replacement_grant = replacement.authorization_grant
        changed = {**payload, "grant_binding_id": str(replacement_grant.binding_id), "authorization_generation": str(replacement.authorization_generation)}
        with patch("bots.zoom_retention.requests.post") as remote:
            self.assertEqual(self.post(changed).status_code, 409)
            self.assertEqual(self.post(payload).status_code, 409)
            remote.assert_not_called()
        self.assertEqual(ZoomRemovalOperation.objects.count(), 1)
        self.assert_replacement(replacement)

    def test_replacement_after_admission_before_claim_preserves_B(self):
        claim = service._claim_operation
        replacements = []

        def competing_claim(operation):
            replacement, error = self.reconnect()
            self.assertIsNone(error)
            replacements.append(replacement)
            return claim(operation)

        with patch("bots.zoom_retention._claim_operation", side_effect=competing_claim), patch("bots.zoom_retention.requests.post") as remote:
            result = self.call(self.payload())
            remote.assert_not_called()
        self.assertEqual(result.state, "revoke_unknown")
        self.assert_replacement(replacements[0])

    def test_replacement_during_refresh_cannot_persist_or_revoke_new_credentials(self):
        replacements = []

        def refresh(*args, **kwargs):
            replacement, error = self.reconnect()
            self.assertIsNone(error)
            replacements.append(replacement)
            return response(200, {"access_token": "old-refresh-access-A", "refresh_token": "old-refresh-A2"})

        with patch("bots.zoom_retention.requests.post", side_effect=refresh) as remote:
            result = self.call(self.payload())
        self.assertEqual(remote.call_count, 1)
        self.assertEqual(result.state, "revoke_unknown")
        self.assertEqual(result.failure_code, "refresh_persist_failed")
        self.assert_replacement(replacements[0])

    def test_replacement_before_pending_token_persistence_preserves_new_credentials(self):
        original = ZoomOAuthConnection.set_credentials
        replacements = []

        def persist(instance, credentials):
            if service.PENDING_REVOKE_ACCESS_TOKEN_KEY in credentials:
                replacement, error = self.reconnect()
                self.assertIsNone(error)
                replacements.append(replacement)
            return original(instance, credentials)

        with patch.object(ZoomOAuthConnection, "set_credentials", new=persist), patch("bots.zoom_retention.requests.post", return_value=response(200, {"access_token": "access-A"})) as remote:
            result = self.call(self.payload())
        self.assertEqual(remote.call_count, 1)
        self.assertEqual(result.state, "revoke_unknown")
        self.assert_replacement(replacements[0])

    def test_reconnect_during_revoke_keeps_captured_token_and_preserves_B_on_final_delete(self):
        self.connection.set_credentials({"refresh_token": "refresh-A", service.PENDING_REVOKE_ACCESS_TOKEN_KEY: "access-A"})
        entered, release = Event(), Event()
        captured = []

        def revoke(*args, **kwargs):
            captured.append(kwargs["data"]["token"])
            entered.set()
            if not release.wait(15):
                raise AssertionError("reconnect did not complete")
            return response(200, {"status": "success"})

        def worker():
            close_old_connections()
            try:
                return self.call(self.payload())
            finally:
                close_old_connections()

        with patch("bots.zoom_retention.requests.post", side_effect=revoke), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(worker)
            try:
                self.assertTrue(entered.wait(15))
                replacement, error = self.reconnect()
                self.assertIsNone(error)
                self.assert_replacement(replacement)
            finally:
                release.set()
            result = future.result(15)
        self.assertEqual(captured, ["access-A"])
        self.assertEqual(result.state, "revoke_unknown")
        self.assertIsNone(result.provider_revoke_settled_at)
        self.assert_replacement(replacement)

    def test_timeout_invalid_grant_404_and_malformed_remain_unproved(self):
        payload = self.payload()
        cases = [requests.Timeout(), response(400, {"error": "invalid_grant"}), response(404, {}), response(200, ["malformed"])]
        for answer in cases:
            with self.subTest(answer=type(answer).__name__), patch("bots.zoom_retention.requests.post", side_effect=[answer]):
                result = self.call(payload)
            self.assertEqual(result.state, "revoke_unknown")
            self.assertIsNone(result.provider_revoke_settled_at)
            self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())

    def test_pending_A_token_unknown_revoke_results_never_prove_removal(self):
        self.connection.set_credentials({"refresh_token": "refresh-A", service.PENDING_REVOKE_ACCESS_TOKEN_KEY: "access-A"})
        payload = self.payload()
        for answer in (requests.Timeout(), response(400, {"error": "invalid_grant"}), response(404, {}), response(200, ["malformed"])):
            with self.subTest(answer=type(answer).__name__), patch("bots.zoom_retention.requests.post", side_effect=[answer]) as remote:
                result = self.call(payload)
            self.assertEqual(remote.call_args.kwargs["data"], {"token": "access-A"})
            self.assertEqual(result.state, "revoke_unknown")
            self.assertIsNone(result.provider_revoke_settled_at)
            self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
