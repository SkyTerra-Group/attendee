import base64
import hashlib
import hmac
import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from datetime import timezone as datetime_timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.db import IntegrityError, close_old_connections, transaction
from django.test import Client, SimpleTestCase, TransactionTestCase, override_settings

from attendee.logging import ZoomTrustBoundaryRedactionFilter
from bots.models import (
    ApiKey,
    Organization,
    Project,
    WebhookDeliveryAttempt,
    WebhookSubscription,
    WebhookTriggerTypes,
    ZoomDeauthorizationAssertionReceipt,
    ZoomDeauthorizationEventBinding,
    ZoomDeauthorizationResolutionOutcomes,
    ZoomDeauthorizationTargetResolution,
    ZoomMeetingToZoomOAuthConnectionMapping,
    ZoomOAuthApp,
    ZoomOAuthAuthorizationGrant,
    ZoomOAuthAuthorizationLineage,
    ZoomOAuthConnection,
    ZoomRemovalOperation,
    ZoomRemovalOperationIdentifier,
    ZoomRemovalOperationIdentifierRoles,
    ZoomRemovalOperationSources,
    ZoomRemovalOperationStates,
    ZoomRemovalOperationTypes,
)
from bots.serializers import ZoomOAuthConnectionSerializer
from bots.tasks.refresh_zoom_oauth_connection_task import refresh_zoom_oauth_connection
from bots.zoom_deauthorization import (
    _candidate_snapshot,
    binding_temporal_evidence_digest,
    candidate_temporal_evidence_digest,
)
from bots.zoom_deauthorization_assertion import (
    ASSERTION_TYP,
    CREATE_IF_FRESH,
    EXISTING_ONLY,
    RESOLVE_PURPOSE,
    SETTLE_PURPOSE,
    TEMPORAL_POLICY,
    AssertionRejected,
    verify_deauthorization_assertion,
)
from bots.zoom_deauthorization_grants import database_clock_now, expected_client_id_digest, provider_identity_digest
from bots.zoom_oauth_connections_api_utils import create_zoom_oauth_connection
from bots.zoom_retention import (
    ProviderOutcome,
    _claim_alternate_identifier,
    _get_or_create_operation,
    delete_expired_receipts,
    process_connection_revoke,
)

TEST_PRIVATE_SEED = bytes(range(32))
TEST_KID = "zd-test-2026-10-19"
TEST_ISSUER = "https://client-agent.test"
TEST_AUDIT_KEY = "test-only-removal-audit-key-32-bytes-minimum"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sign_claims(claims, *, private_key=None, header=None):
    private_key = private_key or Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_SEED)
    header = header or {"alg": "EdDSA", "kid": TEST_KID, "typ": ASSERTION_TYP}
    header_segment = b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    payload_segment = b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    return f"{header_segment}.{payload_segment}.{b64url(private_key.sign(signing_input))}"


class ZoomDeauthorizationVectorTests(SimpleTestCase):
    def test_public_fixed_settlement_vector_is_byte_exact_and_verifies(self):
        fixture = json.loads(
            (Path(__file__).with_name("fixtures") / "zoom_deauthorization_vectors.json").read_text()
        )
        seed = base64.urlsafe_b64decode(fixture["private_seed_b64url"] + "=")
        generated = sign_claims(
            fixture["settlement_claims"],
            private_key=Ed25519PrivateKey.from_private_bytes(seed),
            header=fixture["header"],
        )
        self.assertEqual(generated, fixture["compact_jws"])
        self.assertEqual(hashlib.sha256(generated.encode("ascii")).hexdigest(), fixture["compact_jws_sha256"])
        claims = fixture["settlement_claims"]
        registry = {
            claims["project_id"]: {
                claims["zoom_oauth_app_binding"]: {
                    "zoom_oauth_app_id": 1,
                    "expected_client_id_digest": "0" * 64,
                    "issuer": claims["iss"],
                    "audience": claims["aud"],
                    "keys": {fixture["header"]["kid"]: fixture["public_key_b64url"]},
                }
            }
        }
        with override_settings(ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry):
            verified = verify_deauthorization_assertion(
                generated,
                project=SimpleNamespace(object_id=claims["project_id"]),
                purpose=SETTLE_PURPOSE,
                received_at=datetime.fromtimestamp(claims["iat"], tz=datetime_timezone.utc),
            )
        self.assertEqual(verified.claims, claims)

    def test_public_temporal_evidence_vector_is_byte_exact(self):
        fixture = json.loads(
            (Path(__file__).with_name("fixtures") / "zoom_deauthorization_vectors.json").read_text()
        )["temporal_evidence_vector"]
        snapshot = fixture["snapshot"]
        ordered = [
            snapshot["temporal_policy"],
            snapshot["zoom_event_at"],
            snapshot["zoom_request_signed_at"],
            snapshot["first_verified_at"],
            snapshot["binding_attempt_iat"],
            snapshot["zoom_event_precision_ms"],
            snapshot["zoom_request_precision_ms"],
            snapshot["generation_started_at"],
            snapshot["generation_ended_at"],
            snapshot["client_clock_health_id"],
            snapshot["attendee_boundary_clock_health_ids"],
            snapshot["grant_binding_id"],
            snapshot["connection_generation"],
            snapshot["lineage_sequence"],
            snapshot["history_complete"],
        ]
        canonical_candidate = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(canonical_candidate, fixture["canonical_candidate_json"])
        candidate_digest = candidate_temporal_evidence_digest(snapshot)
        self.assertEqual(candidate_digest, fixture["candidate_evidence_digest"])
        canonical_binding = json.dumps(
            [candidate_digest, fixture["event_binding_id"], fixture["event_binding_version"]],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        self.assertEqual(canonical_binding, fixture["canonical_binding_json"])
        self.assertEqual(
            binding_temporal_evidence_digest(
                candidate_digest,
                uuid.UUID(fixture["event_binding_id"]),
                fixture["event_binding_version"],
            ),
            fixture["binding_evidence_digest"],
        )

    def test_access_log_filter_removes_object_ids_and_query_values(self):
        record = logging.LogRecord(
            "django.request",
            logging.WARNING,
            __file__,
            1,
            "Bad Request: %s",
            (
                "/external_webhooks/zoom/oauth_apps/"
                "zoa_LOG_CANARY_1234?code=authorization-code-canary&state=state-canary",
            ),
            None,
        )
        ZoomTrustBoundaryRedactionFilter().filter(record)
        rendered = record.getMessage()
        for marker in ("zoa_LOG_CANARY_1234", "authorization-code-canary", "state-canary"):
            self.assertNotIn(marker, rendered)
        self.assertIn("[redacted-id]", rendered)
        self.assertIn("?[redacted-query]", rendered)


@override_settings(
    ENABLE_ZOOM_RETENTION_REMOVAL_API=True,
    ZOOM_REMOVAL_AUDIT_KEY=TEST_AUDIT_KEY,
    ZOOM_DEAUTH_DB_CLOCK_HEALTH_ID="attendee-db-clock-test-v1",
    ZOOM_DEAUTH_DB_CLOCK_ERROR_MS=0,
    ZOOM_DEAUTH_DB_CLOCK_CONTINUOUS=True,
    LOG_BOT_STATE_CHANGES=False,
)
class ZoomSignedDeauthorizationTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.organization = Organization.objects.create(name="Signed Deauthorization Tests")
        self.project = Project.objects.create(organization=self.organization, name="Project A")
        self.other_project = Project.objects.create(organization=self.organization, name="Project B")
        _key, self.api_key = ApiKey.create(self.project, "deauth-a")
        _other_key, self.other_api_key = ApiKey.create(self.other_project, "deauth-b")
        self.client = Client()
        self.app_binding = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        self.zoom_app = ZoomOAuthApp.objects.create(
            project=self.project,
            client_id="client-a",
            deauthorization_binding_id=self.app_binding,
        )
        self.zoom_app.set_credentials({"client_secret": "client-secret-a", "webhook_secret": "webhook-secret-a"})
        self.private_key = Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_SEED)
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.audience = f"urn:attendee:test:{self.project.object_id}:{self.app_binding}:zoom-deauthorization"
        self.registry = {
            self.project.object_id: {
                str(self.app_binding): {
                    "zoom_oauth_app_id": self.zoom_app.pk,
                    "expected_client_id_digest": expected_client_id_digest(self.zoom_app.client_id),
                    "issuer": TEST_ISSUER,
                    "audience": self.audience,
                    "keys": {TEST_KID: b64url(public_key)},
                }
            }
        }
        self.registry_override = override_settings(ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=self.registry)
        self.registry_override.enable()
        self.now = int(database_clock_now().timestamp())
        self.connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_app,
            user_id="user-marker-A",
            account_id="account-marker-A",
            authorization_generation=uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        )
        self.connection.set_credentials({"refresh_token": "refresh-marker-A"})
        identity_digest = provider_identity_digest(
            self.project,
            self.zoom_app,
            self.connection.user_id,
            self.connection.account_id,
        )
        self.lineage = ZoomOAuthAuthorizationLineage.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            identity_digest=identity_digest,
            latest_grant_sequence=1,
            has_prior_grant=False,
            history_complete=True,
        )
        self.grant = ZoomOAuthAuthorizationGrant.objects.create(
            binding_id=uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            lineage=self.lineage,
            grant_sequence=1,
            live_connection=self.connection,
            connection_digest="d" * 64,
            identity_digest=identity_digest,
            authorization_generation=self.connection.authorization_generation,
            generation_started_at=datetime.fromtimestamp(self.now - 600, tz=datetime_timezone.utc),
            start_clock_health_id="attendee-db-clock-test-v1",
            start_clock_error_ms=0,
            start_clock_continuous=True,
            legacy_history=False,
        )

    def tearDown(self):
        self.registry_override.disable()

    def replace_grant_fixture(self, *, lineage_overrides=None, **grant_overrides):
        """Build a different immutable history fixture instead of rewriting it."""

        grant_values = {
            "binding_id": self.grant.binding_id,
            "project": self.project,
            "zoom_oauth_app": self.zoom_app,
            "grant_sequence": self.grant.grant_sequence,
            "live_connection": self.connection,
            "connection_digest": self.grant.connection_digest,
            "identity_digest": self.grant.identity_digest,
            "authorization_generation": self.grant.authorization_generation,
            "generation_started_at": self.grant.generation_started_at,
            "start_clock_health_id": self.grant.start_clock_health_id,
            "start_clock_error_ms": self.grant.start_clock_error_ms,
            "start_clock_continuous": self.grant.start_clock_continuous,
            "legacy_history": self.grant.legacy_history,
        }
        self.grant.delete()
        if lineage_overrides:
            identity_digest = self.lineage.identity_digest
            self.lineage.delete()
            lineage_values = {
                "project": self.project,
                "zoom_oauth_app": self.zoom_app,
                "identity_digest": identity_digest,
                "latest_grant_sequence": 1,
                "has_prior_grant": False,
                "history_complete": True,
            }
            lineage_values.update(lineage_overrides)
            self.lineage = ZoomOAuthAuthorizationLineage.objects.create(**lineage_values)
        grant_values["lineage"] = self.lineage
        grant_values.update(grant_overrides)
        self.grant = ZoomOAuthAuthorizationGrant.objects.create(**grant_values)
        return self.grant

    def common_claims(self, *, purpose, mode=CREATE_IF_FRESH, event_id=None, event_at=None, request_at=None, first_at=None, iat=None):
        iat = self.now if iat is None else iat
        event_at = iat if event_at is None else event_at
        request_at = iat if request_at is None else request_at
        first_at = iat if first_at is None else first_at
        return {
            "v": 1,
            "iss": TEST_ISSUER,
            "aud": self.audience,
            "purpose": purpose,
            "binding_mode": mode,
            "project_id": self.project.object_id,
            "zoom_oauth_app_binding": str(self.app_binding),
            "zoom_event_id": event_id or f"zev_{uuid.uuid4().hex}",
            "zoom_event_at": event_at,
            "zoom_request_signed_at": request_at,
            "first_verified_at": first_at,
            "zoom_event_precision_ms": 1000,
            "zoom_request_precision_ms": 1000,
            "temporal_policy": TEMPORAL_POLICY,
            "client_clock_health_id": "client-db-clock-test-v1",
            "client_clock_continuous": True,
            "client_clock_step_free": True,
            "client_clock_error_ms": 0,
            "iat": iat,
            "nbf": iat - 1,
            "exp": iat + 120,
            "jti": str(uuid.uuid4()),
        }

    def settle_claims(self, **kwargs):
        operation_id = kwargs.pop("operation_id", uuid.uuid4())
        claims = self.common_claims(purpose=SETTLE_PURPOSE, **kwargs)
        claims.update(
            {
                "operation_id": str(operation_id),
                "grant_binding_id": str(self.grant.binding_id),
                "connection_digest": self.grant.connection_digest,
                "connection_generation": str(self.grant.authorization_generation),
            }
        )
        snapshot = _candidate_snapshot(
            SimpleNamespace(
                claims=claims,
                received_at=datetime.fromtimestamp(claims["iat"], tz=datetime_timezone.utc),
            ),
            self.grant,
        )
        claims["temporal_evidence_digest"] = candidate_temporal_evidence_digest(snapshot)
        return claims

    def resolve_claims(self, **kwargs):
        claims = self.common_claims(purpose=RESOLVE_PURPOSE, **kwargs)
        claims.update(
            {
                "zoom_client_id": self.zoom_app.client_id,
                "zoom_user_id": self.connection.user_id,
                "zoom_account_id": self.connection.account_id,
            }
        )
        return claims

    def post_assertion(self, path, claims, *, api_key=None, assertion=None):
        return self.client.post(
            path,
            data=json.dumps({"assertion": assertion or sign_claims(claims, private_key=self.private_key)}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Token {api_key or self.api_key}",
        )

    def test_valid_fresh_settlement_deletes_exact_generation_without_provider_call(self):
        mapping = ZoomMeetingToZoomOAuthConnectionMapping.objects.create(
            zoom_oauth_connection=self.connection,
            zoom_oauth_app=self.zoom_app,
            meeting_id="meeting-marker-A",
        )
        subscription = WebhookSubscription.objects.create(project=self.project, url="https://example.test/hook")
        delivery = WebhookDeliveryAttempt.objects.create(
            webhook_subscription=subscription,
            webhook_trigger_type=WebhookTriggerTypes.ZOOM_OAUTH_CONNECTION_STATE_CHANGE,
            idempotency_key=uuid.uuid4(),
            zoom_oauth_connection=self.connection,
            payload={"marker": "event-payload-marker-A"},
        )
        claims = self.settle_claims()
        with patch("bots.zoom_retention._revoke_at_zoom") as revoke:
            response = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["terminal_basis"], "signed_zoom_deauthorization")
        self.assertTrue(response.json()["evidence"]["signed_deauthorization"])
        self.assertFalse(response.json()["evidence"]["provider_revoke"])
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
        self.assertFalse(ZoomMeetingToZoomOAuthConnectionMapping.objects.filter(pk=mapping.pk).exists())
        self.assertFalse(WebhookDeliveryAttempt.objects.filter(pk=delivery.pk).exists())
        self.assertEqual(ZoomDeauthorizationEventBinding.objects.count(), 1)
        self.assertEqual(ZoomDeauthorizationAssertionReceipt.objects.count(), 1)
        revoke.assert_not_called()
        rendered = response.content.decode()
        for marker in (self.connection.user_id, self.connection.account_id, self.connection.object_id, "refresh-marker-A", claims["zoom_event_id"]):
            self.assertNotIn(marker, rendered)

    def test_duplicate_nonce_and_bound_create_are_non_mutating(self):
        claims = self.settle_claims()
        assertion = sign_claims(claims, private_key=self.private_key)
        first = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims, assertion=assertion)
        self.assertEqual(first.status_code, 200)
        counts = (
            ZoomRemovalOperation.objects.count(),
            ZoomDeauthorizationEventBinding.objects.count(),
            ZoomDeauthorizationAssertionReceipt.objects.count(),
        )
        replay = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims, assertion=assertion)
        self.assertEqual(replay.status_code, 409)
        self.assertEqual(replay.json()["error"], "assertion_replayed")
        self.assertEqual(
            counts,
            (
                ZoomRemovalOperation.objects.count(),
                ZoomDeauthorizationEventBinding.objects.count(),
                ZoomDeauthorizationAssertionReceipt.objects.count(),
            ),
        )

        claims["jti"] = str(uuid.uuid4())
        recovery = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(recovery.status_code, 409)
        self.assertEqual(recovery.json()["error"], "binding_already_exists")
        self.assertIn("event_binding_id", recovery.json())
        self.assertEqual(ZoomDeauthorizationAssertionReceipt.objects.count(), 1)

    def test_one_grant_operation_cannot_bind_two_distinct_provider_events(self):
        first = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            self.resolve_claims(),
        )
        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(first.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.RESOLVED)

        second = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            self.resolve_claims(),
        )
        self.assertEqual(second.status_code, 409)
        self.assertEqual(second.json()["error"], "event_binding_conflict")
        self.assertEqual(ZoomDeauthorizationEventBinding.objects.count(), 1)
        self.assertEqual(ZoomRemovalOperation.objects.count(), 1)

    def test_existing_only_retries_frozen_binding_after_horizon(self):
        claims = self.settle_claims()
        first = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(first.status_code, 200)
        binding = ZoomDeauthorizationEventBinding.objects.get()
        claims.update(
            {
                "binding_mode": EXISTING_ONLY,
                "jti": str(uuid.uuid4()),
                "iat": self.now + 600,
                "nbf": self.now + 599,
                "exp": self.now + 720,
                "temporal_evidence_digest": binding.binding_evidence_digest,
            }
        )
        with patch("bots.zoom_deauthorization.database_clock_now", return_value=datetime.fromtimestamp(self.now + 600, tz=datetime_timezone.utc)), patch(
            "bots.zoom_retention_api_views.database_clock_now",
            return_value=datetime.fromtimestamp(self.now + 600, tz=datetime_timezone.utc),
        ):
            replay = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(ZoomDeauthorizationEventBinding.objects.count(), 1)
        self.assertEqual(ZoomRemovalOperation.objects.count(), 1)

    def test_existing_only_resolver_miss_is_target_free_and_never_matches(self):
        claims = self.resolve_claims(mode=EXISTING_ONLY)
        with patch("bots.zoom_deauthorization.provider_identity_digest") as identity_matcher:
            response = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", claims)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND)
        identity_matcher.assert_not_called()
        resolution = ZoomDeauthorizationTargetResolution.objects.get()
        self.assertIsNone(resolution.authorization_grant_id)
        self.assertIsNone(resolution.operation_id)
        self.assertIsNone(resolution.connection_digest)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())

        claims["binding_mode"] = CREATE_IF_FRESH
        claims["jti"] = str(uuid.uuid4())
        later = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", claims)
        self.assertEqual(later.status_code, 200)
        self.assertEqual(later.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())

    def test_existing_only_settlement_miss_is_target_free_and_never_matches(self):
        claims = self.settle_claims(mode=EXISTING_ONLY)
        with patch("bots.zoom_deauthorization.ZoomOAuthAuthorizationGrant.objects.filter") as candidate_query:
            response = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND)
        candidate_query.assert_not_called()

        resolution = ZoomDeauthorizationTargetResolution.objects.get()
        self.assertEqual(resolution.outcome, ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND)
        self.assertIsNone(resolution.event_binding_id)
        self.assertIsNone(resolution.authorization_grant_id)
        self.assertIsNone(resolution.operation_id)
        self.assertIsNone(resolution.grant_binding_id)
        self.assertIsNone(resolution.connection_digest)
        self.assertIsNone(resolution.authorization_generation)
        self.assertIsNone(resolution.binding_evidence_digest)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())
        self.assertFalse(ZoomDeauthorizationAssertionReceipt.objects.exists())

        claims["binding_mode"] = CREATE_IF_FRESH
        claims["jti"] = str(uuid.uuid4())
        later = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(later.status_code, 409)
        self.assertEqual(later.json()["error"], ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())

    def test_stale_direct_settlement_persists_target_free_quarantine(self):
        claims = self.settle_claims(
            event_at=self.now - 30,
            request_at=self.now,
            first_at=self.now,
            iat=self.now,
        )
        response = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND)
        resolution = ZoomDeauthorizationTargetResolution.objects.get()
        self.assertEqual(resolution.outcome, ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND)
        self.assertIsNone(resolution.authorization_grant_id)
        self.assertIsNone(resolution.operation_id)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())
        self.assertFalse(ZoomDeauthorizationAssertionReceipt.objects.exists())

    def test_four_timestamp_horizon_29_succeeds_and_30_is_durable_unbound(self):
        fresh = self.resolve_claims(event_at=self.now - 29, request_at=self.now, first_at=self.now, iat=self.now)
        accepted = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", fresh)
        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.assertEqual(accepted.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.RESOLVED)
        self.assertEqual(ZoomDeauthorizationEventBinding.objects.count(), 1)

        ZoomDeauthorizationAssertionReceipt.objects.all().delete()
        ZoomDeauthorizationTargetResolution.objects.all().delete()
        ZoomDeauthorizationEventBinding.objects.all().delete()
        ZoomRemovalOperation.objects.all().delete()
        self.grant.canonical_removal_operation = None
        self.grant.save(update_fields=["canonical_removal_operation", "updated_at"])
        stale = self.resolve_claims(event_at=self.now - 30, request_at=self.now, first_at=self.now, iat=self.now)
        rejected = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", stale)
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(rejected.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())

    def test_event_after_signed_request_is_durable_temporal_quarantine(self):
        claims = self.resolve_claims(event_at=self.now + 1, request_at=self.now)
        response = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            claims,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["outcome"],
            ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_TEMPORAL_ORDER,
        )
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())

    def test_whole_u62_interval_is_strict_and_boundary_touch_quarantines(self):
        self.replace_grant_fixture(
            generation_started_at=datetime.fromtimestamp(self.now - 62, tz=datetime_timezone.utc)
        )
        response = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            self.resolve_claims(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_TEMPORAL_ORDER)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())

    def test_incomplete_or_prior_lineage_never_time_binds(self):
        self.replace_grant_fixture(
            lineage_overrides={"history_complete": False, "has_prior_grant": True, "latest_grant_sequence": 2}
        )
        response = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            self.resolve_claims(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_PROVIDER_CLOCK)
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())

    def test_clock_and_precision_claims_fail_closed(self):
        cases = [
            ("client_clock_continuous", False, "clock_untrusted"),
            ("client_clock_step_free", False, "clock_untrusted"),
            ("client_clock_error_ms", 1001, "clock_error_invalid"),
            ("zoom_event_precision_ms", 1001, "event_precision_invalid"),
        ]
        for field, value, code in cases:
            with self.subTest(field=field):
                claims = self.resolve_claims()
                claims[field] = value
                response = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", claims)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()["error"], code)
        self.assertFalse(ZoomDeauthorizationAssertionReceipt.objects.exists())

    def test_combined_clock_error_over_one_second_is_durable_clock_untrusted(self):
        self.replace_grant_fixture(start_clock_error_ms=1)
        claims = self.resolve_claims()
        claims["client_clock_error_ms"] = 1000
        response = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", claims)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.CLOCK_UNTRUSTED)

    def test_wrong_signature_project_audience_app_and_unknown_claim_change_nothing(self):
        cases = []
        claims = self.settle_claims()
        cases.append(sign_claims(claims, private_key=Ed25519PrivateKey.generate()))
        wrong_audience = dict(claims, aud="urn:wrong")
        wrong_audience["jti"] = str(uuid.uuid4())
        cases.append(sign_claims(wrong_audience, private_key=self.private_key))
        unknown = dict(claims, unexpected="no")
        unknown["jti"] = str(uuid.uuid4())
        cases.append(sign_claims(unknown, private_key=self.private_key))
        for assertion in cases:
            response = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims, assertion=assertion)
            self.assertEqual(response.status_code, 401)
        cross_project = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization",
            claims,
            api_key=self.other_api_key,
        )
        self.assertEqual(cross_project.status_code, 401)
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())

    def test_algorithm_confusion_and_noncanonical_token_rejected(self):
        claims = self.settle_claims()
        for header in (
            {"alg": "none", "kid": TEST_KID, "typ": ASSERTION_TYP},
            {"alg": "HS256", "kid": TEST_KID, "typ": ASSERTION_TYP},
            {"alg": "EdDSA", "kid": TEST_KID, "typ": "JWT"},
            {"alg": "EdDSA", "kid": TEST_KID, "typ": ASSERTION_TYP, "x": "y"},
        ):
            response = self.post_assertion(
                "/api/v1/zoom_retention/deauthorization",
                claims,
                assertion=sign_claims(claims, private_key=self.private_key, header=header),
            )
            self.assertEqual(response.status_code, 401)
        token = sign_claims(claims, private_key=self.private_key)
        padded = token.split(".")
        padded[0] += "="
        response = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims, assertion=".".join(padded))
        self.assertEqual(response.status_code, 401)

    def test_assertion_receipt_clock_gate_accepts_exact_30_seconds_only(self):
        claims = self.settle_claims()
        claims["nbf"] = self.now - 30
        claims["exp"] = self.now + 270
        assertion = sign_claims(claims, private_key=self.private_key)
        for delta in (-30, 30):
            with self.subTest(delta=delta):
                verified = verify_deauthorization_assertion(
                    assertion,
                    project=self.project,
                    purpose=SETTLE_PURPOSE,
                    received_at=datetime.fromtimestamp(
                        self.now + delta,
                        tz=datetime_timezone.utc,
                    ),
                )
                self.assertEqual(verified.claims_digest, hashlib.sha256(".".join(assertion.split(".")[:2]).encode("ascii")).hexdigest())
        for delta in (-30.001, 30.001):
            with self.subTest(delta=delta), self.assertRaises(AssertionRejected):
                verify_deauthorization_assertion(
                    assertion,
                    project=self.project,
                    purpose=SETTLE_PURPOSE,
                    received_at=datetime.fromtimestamp(
                        self.now + delta,
                        tz=datetime_timezone.utc,
                    ),
                )

    def test_shared_identifier_registry_reads_canonical_and_alternate(self):
        claims = self.settle_claims()
        first = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(first.status_code, 200)
        canonical = first.json()["operation_id"]
        binding = ZoomDeauthorizationEventBinding.objects.get()
        alternate = uuid.uuid4()
        claims.update(
            {
                "operation_id": str(alternate),
                "binding_mode": EXISTING_ONLY,
                "temporal_evidence_digest": binding.binding_evidence_digest,
                "jti": str(uuid.uuid4()),
            }
        )
        second = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["operation_id"], canonical)
        for identifier in (canonical, str(alternate)):
            readback = self.client.get(
                f"/api/v1/zoom_retention/operations/{identifier}",
                HTTP_AUTHORIZATION=f"Token {self.api_key}",
            )
            self.assertEqual(readback.status_code, 200)
            self.assertEqual(readback.json()["operation_id"], canonical)
            self.assertEqual(readback.json()["event_binding_id"], str(binding.binding_id))

    def test_resolver_supplied_binding_requires_exact_resolution_receipt(self):
        event_id = f"zev_{uuid.uuid4().hex}"
        resolved = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            self.resolve_claims(event_id=event_id),
        )
        self.assertEqual(resolved.status_code, 200, resolved.content)
        settlement = self.settle_claims(
            event_id=event_id,
            operation_id=uuid.UUID(resolved.json()["operation_id"]),
            mode=EXISTING_ONLY,
        )
        settlement["temporal_evidence_digest"] = resolved.json()[
            "temporal_evidence_digest"
        ]
        missing = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization",
            settlement,
        )
        self.assertEqual(missing.status_code, 409)
        self.assertEqual(missing.json()["error"], "resolution_mismatch")
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())

        settlement["resolution_id"] = resolved.json()["resolution_id"]
        settlement["jti"] = str(uuid.uuid4())
        accepted = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization",
            settlement,
        )
        self.assertEqual(accepted.status_code, 200, accepted.content)

    def test_provider_first_and_signed_first_converge_without_second_provider_call(self):
        event_id = f"zev_{uuid.uuid4().hex}"
        resolver_claims = self.resolve_claims(event_id=event_id)
        resolved = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            resolver_claims,
        )
        self.assertEqual(resolved.status_code, 200, resolved.content)
        self.assertEqual(resolved.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.RESOLVED)
        canonical = uuid.UUID(resolved.json()["operation_id"])
        connection_id = self.connection.object_id

        with patch("bots.zoom_retention._revoke_at_zoom", return_value=ProviderOutcome(True)) as provider:
            provider_result = process_connection_revoke(
                project=self.project,
                operation_id=canonical,
                connection_object_id=connection_id,
                source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
            )
        self.assertEqual(provider_result.terminal_basis, "provider_revoke")
        provider.assert_called_once()

        settlement = self.settle_claims(
            mode=EXISTING_ONLY,
            event_id=event_id,
            operation_id=canonical,
        )
        settlement["resolution_id"] = resolved.json()["resolution_id"]
        settlement["temporal_evidence_digest"] = resolved.json()["temporal_evidence_digest"]
        with patch("bots.zoom_retention._revoke_at_zoom") as second_provider:
            signed = self.post_assertion("/api/v1/zoom_retention/deauthorization", settlement)
        self.assertEqual(signed.status_code, 200, signed.content)
        self.assertEqual(signed.json()["operation_id"], str(canonical))
        self.assertEqual(signed.json()["terminal_basis"], "provider_and_signed")
        self.assertTrue(signed.json()["evidence"]["provider_revoke"])
        self.assertTrue(signed.json()["evidence"]["signed_deauthorization"])
        second_provider.assert_not_called()

        # A signed-first operation is already terminal. The ordinary revoke
        # route resolves the same registry entry and never starts provider I/O.
        self.connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_app,
            user_id="user-marker-signed-first",
            account_id="account-marker-signed-first",
            authorization_generation=uuid.uuid4(),
        )
        self.connection.set_credentials({"refresh_token": "signed-first-refresh"})
        identity = provider_identity_digest(
            self.project,
            self.zoom_app,
            self.connection.user_id,
            self.connection.account_id,
        )
        lineage = ZoomOAuthAuthorizationLineage.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            identity_digest=identity,
            latest_grant_sequence=1,
            history_complete=True,
        )
        self.grant = ZoomOAuthAuthorizationGrant.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            lineage=lineage,
            grant_sequence=1,
            live_connection=self.connection,
            connection_digest="a" * 64,
            identity_digest=identity,
            authorization_generation=self.connection.authorization_generation,
            generation_started_at=datetime.fromtimestamp(self.now - 600, tz=datetime_timezone.utc),
            start_clock_health_id="attendee-db-clock-test-v1",
            start_clock_error_ms=0,
            start_clock_continuous=True,
        )
        connection_id = self.connection.object_id
        direct = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization",
            self.settle_claims(),
        )
        self.assertEqual(direct.status_code, 200, direct.content)
        signed_canonical = uuid.UUID(direct.json()["operation_id"])
        with patch("bots.zoom_retention._revoke_at_zoom") as provider_after_signed:
            replay = process_connection_revoke(
                project=self.project,
                operation_id=signed_canonical,
                connection_object_id=connection_id,
                source=ZoomRemovalOperationSources.SKYTERRA_INITIATED,
            )
        self.assertEqual(str(signed_canonical), str(replay.identifiers.get(role="canonical").identifier_uuid))
        self.assertEqual(replay.terminal_basis, "signed_zoom_deauthorization")
        provider_after_signed.assert_not_called()

    def test_bound_response_loss_recovery_after_reconnect_preserves_new_generation(self):
        event_id = f"zev_{uuid.uuid4().hex}"
        resolver_claims = self.resolve_claims(event_id=event_id)
        resolved = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            resolver_claims,
        )
        self.assertEqual(resolved.status_code, 200, resolved.content)
        old_generation = self.grant.authorization_generation
        token = {
            "access_token": "access-reconnect-marker",
            "refresh_token": "refresh-reconnect-marker",
            "scope": "user:read:user user:read:zak meeting:read:list_meetings meeting:read:local_recording_token",
        }
        user = {"id": self.connection.user_id, "account_id": self.connection.account_id, "status": "active"}
        payload = {
            "zoom_oauth_app_binding": str(self.app_binding),
            "authorization_code": "reconnect-code-marker",
            "redirect_uri": "https://client-agent.test/reconnect",
        }
        with patch("bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens", return_value=token), patch(
            "bots.zoom_oauth_connections_api_utils._get_user_info", return_value=user
        ):
            reconnected, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(error)
        self.assertNotEqual(reconnected.authorization_generation, old_generation)
        new_generation = reconnected.authorization_generation

        recovery_claims = self.resolve_claims(mode=EXISTING_ONLY, event_id=event_id)
        recovery_claims.update({"iat": self.now + 600, "nbf": self.now + 599, "exp": self.now + 720})
        later = datetime.fromtimestamp(self.now + 600, tz=datetime_timezone.utc)
        with patch("bots.zoom_retention_api_views.database_clock_now", return_value=later):
            recovered = self.post_assertion(
                "/api/v1/zoom_retention/deauthorization/resolve",
                recovery_claims,
            )
        self.assertEqual(recovered.status_code, 200, recovered.content)
        self.assertEqual(recovered.json()["event_binding_id"], resolved.json()["event_binding_id"])

        settlement = self.settle_claims(
            mode=EXISTING_ONLY,
            event_id=event_id,
            operation_id=uuid.UUID(resolved.json()["operation_id"]),
        )
        settlement.update(
            {
                "resolution_id": resolved.json()["resolution_id"],
                "temporal_evidence_digest": resolved.json()["temporal_evidence_digest"],
                "iat": self.now + 600,
                "nbf": self.now + 599,
                "exp": self.now + 720,
                "jti": str(uuid.uuid4()),
            }
        )
        with patch("bots.zoom_retention_api_views.database_clock_now", return_value=later), patch(
            "bots.zoom_retention._revoke_at_zoom"
        ) as provider:
            settled = self.post_assertion("/api/v1/zoom_retention/deauthorization", settlement)
        self.assertEqual(settled.status_code, 200, settled.content)
        reconnected.refresh_from_db()
        self.assertEqual(reconnected.authorization_generation, new_generation)
        self.assertEqual(reconnected.state, 1)
        provider.assert_not_called()

    def test_cross_grant_identifier_collision_allocates_independent_canonical(self):
        other_connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_app,
            user_id="collision-user",
            account_id="collision-account",
            authorization_generation=uuid.uuid4(),
        )
        other_connection.set_credentials({"refresh_token": "collision-refresh"})
        other_identity = provider_identity_digest(
            self.project,
            self.zoom_app,
            other_connection.user_id,
            other_connection.account_id,
        )
        other_lineage = ZoomOAuthAuthorizationLineage.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            identity_digest=other_identity,
            latest_grant_sequence=1,
            history_complete=True,
        )
        other_grant = ZoomOAuthAuthorizationGrant.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            lineage=other_lineage,
            grant_sequence=1,
            live_connection=other_connection,
            connection_digest="b" * 64,
            identity_digest=other_identity,
            authorization_generation=other_connection.authorization_generation,
            generation_started_at=datetime.fromtimestamp(self.now - 600, tz=datetime_timezone.utc),
            start_clock_health_id="attendee-db-clock-test-v1",
            start_clock_error_ms=0,
            start_clock_continuous=True,
        )
        other_operation = _get_or_create_operation(
            project=self.project,
            operation_id=uuid.uuid4(),
            operation_type=ZoomRemovalOperationTypes.REVOKE_CONNECTION,
            target_object_id=other_connection.object_id,
            source=ZoomRemovalOperationSources.ZOOM_DEAUTHORIZATION,
            target_generation=other_grant.authorization_generation,
            authorization_grant=other_grant,
        )
        occupied = uuid.uuid4()
        _claim_alternate_identifier(other_operation, occupied)

        claims = self.settle_claims(operation_id=occupied)
        collision = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(collision.status_code, 409, collision.content)
        self.assertEqual(collision.json()["error"], "operation_identifier_conflict")
        own_canonical = collision.json()["operation_id"]
        self.assertNotEqual(own_canonical, str(occupied))
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.filter(event_digest=hashlib.sha256(claims["zoom_event_id"].encode()).hexdigest()).exists())

        own_read = self.client.get(
            f"/api/v1/zoom_retention/operations/{own_canonical}",
            HTTP_AUTHORIZATION=f"Token {self.api_key}",
        )
        occupied_read = self.client.get(
            f"/api/v1/zoom_retention/operations/{occupied}",
            HTTP_AUTHORIZATION=f"Token {self.api_key}",
        )
        self.assertEqual(own_read.status_code, 200)
        self.assertEqual(own_read.json()["grant_binding_id"], str(self.grant.binding_id))
        self.assertEqual(occupied_read.status_code, 200)
        self.assertEqual(occupied_read.json()["grant_binding_id"], str(other_grant.binding_id))

        replay = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(replay.status_code, 409)
        self.assertEqual(replay.json()["error"], "assertion_replayed")
        self.assertEqual(replay.json()["operation_id"], own_canonical)

        claims["operation_id"] = own_canonical
        claims["jti"] = str(uuid.uuid4())
        retry = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(retry.status_code, 200, retry.content)
        self.assertEqual(retry.json()["operation_id"], own_canonical)

    def test_concurrent_create_assertions_converge_on_one_binding_and_delete(self):
        event_id = f"zev_{uuid.uuid4().hex}"
        claims = [
            self.settle_claims(event_id=event_id, operation_id=uuid.uuid4()),
            self.settle_claims(event_id=event_id, operation_id=uuid.uuid4()),
        ]

        def send(one):
            close_old_connections()
            try:
                client = Client()
                return client.post(
                    "/api/v1/zoom_retention/deauthorization",
                    data=json.dumps({"assertion": sign_claims(one, private_key=self.private_key)}),
                    content_type="application/json",
                    HTTP_AUTHORIZATION=f"Token {self.api_key}",
                )
            finally:
                close_old_connections()

        with patch("bots.zoom_retention._revoke_at_zoom") as provider, ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(send, claims))
        self.assertEqual(sorted(response.status_code for response in responses), [200, 409])
        self.assertEqual(ZoomDeauthorizationEventBinding.objects.count(), 1)
        self.assertEqual(ZoomRemovalOperation.objects.filter(authorization_grant=self.grant).count(), 1)
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
        provider.assert_not_called()

    def test_operation_identifier_namespace_rejects_cross_role_and_cross_project(self):
        claims = self.settle_claims()
        response = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(response.status_code, 200)
        operation = ZoomRemovalOperation.objects.get()
        occupied = uuid.uuid4()
        ZoomRemovalOperationIdentifier.objects.create(
            project=self.project,
            identifier_uuid=occupied,
            operation=operation,
            role=ZoomRemovalOperationIdentifierRoles.ALTERNATE,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomRemovalOperationIdentifier.objects.create(
                    project=self.project,
                    identifier_uuid=occupied,
                    operation=operation,
                    role=ZoomRemovalOperationIdentifierRoles.CANONICAL,
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomRemovalOperationIdentifier.objects.create(
                    project=self.other_project,
                    identifier_uuid=uuid.uuid4(),
                    operation=operation,
                    role=ZoomRemovalOperationIdentifierRoles.ALTERNATE,
                )

    def test_database_rejects_registry_bypass_and_immutable_evidence_rewrite(self):
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomOAuthAuthorizationLineage.objects.create(
                    project=self.other_project,
                    zoom_oauth_app=self.zoom_app,
                    identity_digest="9" * 64,
                    latest_grant_sequence=1,
                    history_complete=True,
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomOAuthAuthorizationGrant.objects.create(
                    project=self.project,
                    zoom_oauth_app=self.zoom_app,
                    lineage=self.lineage,
                    grant_sequence=2,
                    connection_digest="8" * 64,
                    identity_digest="7" * 64,
                    authorization_generation=self.connection.authorization_generation,
                    generation_started_at=datetime.fromtimestamp(
                        self.now - 500,
                        tz=datetime_timezone.utc,
                    ),
                    start_clock_health_id="attendee-db-clock-test-v1",
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomRemovalOperation.objects.create(
                    project=self.project,
                    operation_id=uuid.uuid4(),
                    operation_type=ZoomRemovalOperationTypes.PURGE_BOT,
                    target_digest="f" * 64,
                    target_object_id="bot_registrybypass",
                )

        claims = self.settle_claims()
        settled = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(settled.status_code, 200, settled.content)
        binding = ZoomDeauthorizationEventBinding.objects.get()
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomDeauthorizationEventBinding.objects.filter(pk=binding.pk).update(
                    evidence_snapshot={"rewritten": True}
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomOAuthApp.objects.filter(pk=self.zoom_app.pk).update(
                    deauthorization_binding_id=uuid.uuid4()
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomOAuthAuthorizationGrant.objects.filter(pk=self.grant.pk).update(
                    connection_digest="0" * 64
                )
        operation = ZoomRemovalOperation.objects.get()
        other_app = ZoomOAuthApp.objects.create(
            project=self.other_project,
            client_id="client-other",
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomDeauthorizationAssertionReceipt.objects.create(
                    project=self.other_project,
                    zoom_oauth_app=other_app,
                    issuer_id=TEST_ISSUER,
                    key_id=TEST_KID,
                    nonce_digest="6" * 64,
                    claims_digest="5" * 64,
                    purpose=SETTLE_PURPOSE,
                    binding_mode=EXISTING_ONLY,
                    operation=operation,
                    received_at=database_clock_now(),
                    expires_at=database_clock_now() + timedelta(days=1),
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomRemovalOperation.objects.filter(pk=operation.pk).update(
                    state=ZoomRemovalOperationStates.PENDING
                )

    def test_expiry_seals_permanent_event_tombstone_and_prevents_rebinding(self):
        claims = self.settle_claims()
        settled = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(settled.status_code, 200, settled.content)
        operation = ZoomRemovalOperation.objects.get()
        operation.expires_at = database_clock_now() - timedelta(seconds=1)
        operation.save(update_fields=["expires_at", "updated_at"])
        self.assertEqual(delete_expired_receipts(), 1)
        binding = ZoomDeauthorizationEventBinding.objects.get()
        self.assertIsNone(binding.operation_id)
        self.assertIsNone(binding.authorization_grant_id)
        self.assertFalse(ZoomRemovalOperation.objects.exists())
        self.assertFalse(ZoomDeauthorizationAssertionReceipt.objects.exists())

        claims.update(
            {
                "binding_mode": EXISTING_ONLY,
                "temporal_evidence_digest": binding.binding_evidence_digest,
                "jti": str(uuid.uuid4()),
            }
        )
        retry = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(retry.status_code, 409)
        self.assertEqual(retry.json()["error"], "bound_event_result_expired")
        self.assertEqual(ZoomDeauthorizationEventBinding.objects.count(), 1)
        self.assertFalse(ZoomOAuthConnection.objects.exists())

    def test_exact_app_oauth_capture_creates_complete_sequence_then_permanent_sequence_two(self):
        ZoomOAuthAuthorizationGrant.objects.all().delete()
        ZoomOAuthAuthorizationLineage.objects.all().delete()
        ZoomOAuthConnection.objects.all().delete()
        payload = {
            "zoom_oauth_app_binding": str(self.app_binding),
            "authorization_code": "code-marker",
            "redirect_uri": "https://client-agent.test/callback",
        }
        token = {
            "access_token": "access-marker",
            "refresh_token": "refresh-marker",
            "scope": "user:read:user user:read:zak meeting:read:list_meetings meeting:read:local_recording_token",
        }
        user = {"id": "stable-user", "account_id": "stable-account", "status": "active"}
        with patch("bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens", return_value=token), patch(
            "bots.zoom_oauth_connections_api_utils._get_user_info", return_value=user
        ):
            first, error = create_zoom_oauth_connection(payload, self.project)
            self.assertIsNone(error)
            first_grant = first.authorization_grant
            self.assertEqual(first_grant.grant_sequence, 1)
            self.assertTrue(first_grant.lineage.history_complete)
            first_generation = first.authorization_generation
            second, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(error)
        self.assertEqual(first.pk, second.pk)
        self.assertNotEqual(second.authorization_generation, first_generation)
        grants = list(ZoomOAuthAuthorizationGrant.objects.order_by("grant_sequence"))
        self.assertEqual([grant.grant_sequence for grant in grants], [1, 2])
        self.assertIsNotNone(grants[0].generation_ended_at)
        self.assertIsNone(grants[0].live_connection_id)
        self.assertEqual(grants[1].live_connection_id, second.pk)
        grants[0].lineage.refresh_from_db()
        self.assertTrue(grants[0].lineage.has_prior_grant)
        serialized = ZoomOAuthConnectionSerializer(second).data
        self.assertEqual(serialized["zoom_oauth_app_binding"], str(self.app_binding))
        self.assertEqual(serialized["grant_sequence"], 2)

    def test_exact_app_oauth_capture_fails_closed_without_audit_key(self):
        ZoomOAuthAuthorizationGrant.objects.all().delete()
        ZoomOAuthAuthorizationLineage.objects.all().delete()
        ZoomOAuthConnection.objects.all().delete()
        payload = {
            "zoom_oauth_app_binding": str(self.app_binding),
            "authorization_code": "code-marker",
            "redirect_uri": "https://client-agent.test/callback",
        }
        token = {
            "access_token": "access-marker",
            "refresh_token": "refresh-marker",
            "scope": "user:read:user user:read:zak meeting:read:list_meetings meeting:read:local_recording_token",
        }
        user = {"id": "stable-user", "account_id": "stable-account", "status": "active"}
        with override_settings(ZOOM_REMOVAL_AUDIT_KEY=None), patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens", return_value=token
        ), patch("bots.zoom_oauth_connections_api_utils._get_user_info", return_value=user):
            connection, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(connection)
        self.assertEqual(error, {"error": "Zoom authorization lineage could not be recorded safely."})
        self.assertFalse(ZoomOAuthConnection.objects.exists())

    def test_feature_off_hides_signed_routes(self):
        claims = self.settle_claims()
        with override_settings(ENABLE_ZOOM_RETENTION_REMOVAL_API=False):
            response = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(response.status_code, 404)

    def test_new_signed_path_emits_no_raw_claims_or_assertion_to_logs(self):
        claims = self.settle_claims()
        assertion = sign_claims(claims, private_key=self.private_key)
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        handler = Capture()
        logging.getLogger().addHandler(handler)
        try:
            response = self.post_assertion(
                "/api/v1/zoom_retention/deauthorization",
                claims,
                assertion=assertion,
            )
        finally:
            logging.getLogger().removeHandler(handler)
        rendered = response.content.decode() + "\n".join(records)
        self.assertEqual(response.status_code, 200)
        for marker in (
            assertion,
            claims["zoom_event_id"],
            self.connection.user_id,
            self.connection.account_id,
            self.connection.object_id,
            "refresh-marker-A",
        ):
            self.assertNotIn(marker, rendered)

    def test_oauth_callback_and_worker_failures_log_only_bounded_codes(self):
        authorization_marker = "authorization-code-log-canary"
        provider_marker = "provider-exception-log-canary"
        payload = {
            "zoom_oauth_app_binding": str(self.app_binding),
            "authorization_code": authorization_marker,
            "redirect_uri": "https://client-agent.test/callback-log-canary",
        }
        with patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens",
            side_effect=RuntimeError(provider_marker),
        ), self.assertLogs("bots.zoom_oauth_connections_api_utils", level="ERROR") as callback_logs:
            connection, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(connection)
        self.assertIsNotNone(error)
        callback_rendered = "\n".join(callback_logs.output)
        self.assertNotIn(authorization_marker, callback_rendered)
        self.assertNotIn(provider_marker, callback_rendered)

        with patch(
            "bots.tasks.refresh_zoom_oauth_connection_task._get_access_token",
            side_effect=RuntimeError(provider_marker),
        ), self.assertLogs("bots.tasks.refresh_zoom_oauth_connection_task", level="INFO") as worker_logs:
            with self.assertRaises(Exception):
                refresh_zoom_oauth_connection(self.connection.pk)
        worker_rendered = "\n".join(worker_logs.output)
        self.assertNotIn(provider_marker, worker_rendered)
        self.assertNotIn(str(self.connection.pk), worker_rendered)

    def test_zoom_external_webhook_logs_no_raw_body_identifiers(self):
        meeting_marker = "meeting-log-canary"
        host_marker = "host-log-canary"
        operator_marker = "operator-log-canary"
        body = json.dumps(
            {
                "event": "meeting.created",
                "payload": {
                    "object": {"id": meeting_marker, "host_id": host_marker},
                    "operator_id": operator_marker,
                },
            }
        )
        timestamp = str(self.now)
        signature = "v0=" + hmac.new(
            b"webhook-secret-a",
            f"v0:{timestamp}:{body}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        with self.assertLogs("bots.external_webhooks_views", level="INFO") as webhook_logs:
            response = self.client.post(
                f"/external_webhooks/zoom/oauth_apps/{self.zoom_app.object_id}",
                data=body,
                content_type="application/json",
                HTTP_X_ZM_SIGNATURE=signature,
                HTTP_X_ZM_REQUEST_TIMESTAMP=timestamp,
            )
        self.assertEqual(response.status_code, 200)
        rendered = "\n".join(webhook_logs.output)
        for marker in (body, meeting_marker, host_marker, operator_marker, self.zoom_app.object_id):
            self.assertNotIn(marker, rendered)
        self.assertIn("event_type=meeting.created", rendered)
