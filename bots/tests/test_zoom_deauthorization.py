import base64
import hashlib
import hmac
import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from datetime import timezone as datetime_timezone
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import (
    IntegrityError,
    close_old_connections,
    transaction,
)
from django.db import (
    connection as django_db_connection,
)
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.recorder import MigrationRecorder
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
    ZoomOAuthAuthorizationGrantClockSample,
    ZoomOAuthAuthorizationLineage,
    ZoomOAuthConnection,
    ZoomRemovalAuditKeyFingerprint,
    ZoomRemovalOperation,
    ZoomRemovalOperationIdentifier,
    ZoomRemovalOperationIdentifierRoles,
    ZoomRemovalOperationSources,
    ZoomRemovalOperationStates,
    ZoomRemovalOperationTypes,
)
from bots.serializers import ZoomOAuthConnectionSerializer
from bots.tasks.refresh_zoom_oauth_connection_task import refresh_zoom_oauth_connection
from bots.tests.zoom_log_capture import (
    CaptureConfiguredZoomLogBytes,
    CaptureZoomLogBytes,
)
from bots.zoom_deauthorization import (
    DeauthorizationServiceError,
    _candidate_snapshot,
    binding_temporal_evidence_digest,
    candidate_temporal_evidence_digest,
    resolution_result,
)
from bots.zoom_deauthorization_assertion import (
    ASSERTION_TYP,
    CREATE_IF_FRESH,
    EXISTING_ONLY,
    RESOLVE_PURPOSE,
    SETTLE_PURPOSE,
    CLOCK_MEASUREMENT_POLICY,
    TEMPORAL_POLICY,
    TEMPORAL_POLICY_V2,
    AssertionRejected,
    verify_deauthorization_assertion,
)
from bots.zoom_deauthorization_grants import (
    GrantCaptureUnavailable,
    configured_clock_policy,
    connection_binding_digest,
    database_clock_now,
    expected_client_id_digest,
    provider_identity_digest,
)
from bots.zoom_clock_sample import Kernel, LocalProbe, Sample
from bots.zoom_deauthorization_readiness import DeauthorizationReadinessError, collect_readiness
from bots.zoom_oauth_connections_api_utils import create_zoom_oauth_connection
from bots.zoom_removal_audit import (
    AuditKeyringError,
    configured_audit_keyring,
    configured_audit_keyrings,
    key_fingerprint,
)
from bots.zoom_retention import (
    RECEIPT_RETENTION_DAYS,
    DatabaseVerificationError,
    ProviderOutcome,
    _claim_alternate_identifier,
    _get_or_create_operation,
    delete_expired_receipts,
    operation_result,
    process_connection_revoke,
)

TEST_PRIVATE_SEED = bytes(range(32))
TEST_KID = "zd-test-2026-10-19"
TEST_ISSUER = "https://client-agent.test"
TEST_AUDIT_KID = "zar-test-current-v1"
TEST_AUDIT_KEY_RAW = bytes(range(32, 64))
TEST_AUDIT_KEY_FINGERPRINT = hashlib.sha256(TEST_AUDIT_KEY_RAW).hexdigest()
TEST_RING_PROJECT_ID = "proj_test_vector"
TEST_RING_APP_BINDING = uuid.UUID("99999999-9999-4999-8999-999999999999")
TEST_AUDIT_KEYRING_JSON = json.dumps(
    {
        "v": 2,
        "rings": {
            TEST_RING_PROJECT_ID: {
                str(TEST_RING_APP_BINDING): {
                    "current_kid": TEST_AUDIT_KID,
                    "keys": {
                        TEST_AUDIT_KID: base64.urlsafe_b64encode(TEST_AUDIT_KEY_RAW)
                        .rstrip(b"=")
                        .decode("ascii")
                    },
                }
            }
        },
    },
    separators=(",", ":"),
)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def audit_registry_json(entries) -> str:
    rings = {}
    for project_id, app_binding, current_kid, keys in entries:
        rings.setdefault(project_id, {})[str(app_binding)] = {
            "current_kid": current_kid,
            "keys": {kid: b64url(raw) for kid, raw in keys.items()},
        }
    return json.dumps({"v": 2, "rings": rings}, separators=(",", ":"))


def opaque_event_id() -> str:
    return f"zev_{uuid.uuid4().hex}{uuid.uuid4().hex}"


def sign_claims(claims, *, private_key=None, header=None):
    private_key = private_key or Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_SEED)
    header = header or {"alg": "EdDSA", "kid": TEST_KID, "typ": ASSERTION_TYP}
    header_segment = b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    payload_segment = b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    return f"{header_segment}.{payload_segment}.{b64url(private_key.sign(signing_input))}"


class ZoomDeauthorizationVectorTests(SimpleTestCase):
    @override_settings(ZOOM_REMOVAL_AUDIT_KEYRING_JSON=TEST_AUDIT_KEYRING_JSON)
    def test_audit_keyring_contract_is_closed_and_canonical(self):
        registry = configured_audit_keyrings()
        ring = registry.select(TEST_RING_PROJECT_ID, TEST_RING_APP_BINDING)
        self.assertEqual(ring.current_kid, TEST_AUDIT_KID)
        self.assertEqual(ring.current_key, TEST_AUDIT_KEY_RAW)
        self.assertRegex(ring.fingerprint, r"^[0-9a-f]{64}$")
        self.assertRegex(registry.fingerprint, r"^[0-9a-f]{64}$")

        invalid = (
            json.dumps({"v": 1, "rings": {}}),
            json.dumps({"v": 2, "rings": {}}),
            audit_registry_json(
                [(TEST_RING_PROJECT_ID, TEST_RING_APP_BINDING, TEST_AUDIT_KID, {TEST_AUDIT_KID: b"short"})]
            ),
            json.dumps(
                {
                    "v": 2,
                    "rings": {
                        TEST_RING_PROJECT_ID: {
                            str(TEST_RING_APP_BINDING): {
                                "current_kid": "missing",
                                "keys": {TEST_AUDIT_KID: b64url(TEST_AUDIT_KEY_RAW)},
                            }
                        }
                    },
                }
            ),
            json.dumps({"v": 2, "rings": {}, "extra": True}),
            '{"v":2,"v":2,"rings":{}}',
            json.dumps(
                {
                    "v": 2,
                    "rings": {
                        "surrogate-\ud800": {
                            str(TEST_RING_APP_BINDING): {
                                "current_kid": TEST_AUDIT_KID,
                                "keys": {TEST_AUDIT_KID: b64url(TEST_AUDIT_KEY_RAW)},
                            }
                        }
                    },
                }
            ),
            json.dumps(
                {
                    "v": 2,
                    "rings": {
                        TEST_RING_PROJECT_ID: {
                            str(TEST_RING_APP_BINDING): {
                                "current_kid": "surrogate-\ud800",
                                "keys": {"surrogate-\ud800": b64url(TEST_AUDIT_KEY_RAW)},
                            }
                        }
                    },
                }
            ),
        )
        for configured in invalid:
            with self.subTest(configured=configured), override_settings(ZOOM_REMOVAL_AUDIT_KEYRING_JSON=configured):
                with self.assertRaises(AuditKeyringError):
                    configured_audit_keyrings()

    def test_audit_keyring_rejects_duplicate_raw_key_material(self):
        encoded = b64url(TEST_AUDIT_KEY_RAW)
        configured = json.dumps(
            {
                "v": 2,
                "rings": {
                    TEST_RING_PROJECT_ID: {
                        str(TEST_RING_APP_BINDING): {
                            "current_kid": "zar-test-a",
                            "keys": {"zar-test-a": encoded, "zar-test-b": encoded},
                        }
                    }
                },
            }
        )
        with override_settings(ZOOM_REMOVAL_AUDIT_KEYRING_JSON=configured):
            with self.assertRaises(AuditKeyringError) as raised:
                configured_audit_keyrings()
        self.assertEqual(raised.exception.code, "audit_key_conflict")

    def test_audit_keyring_rejects_cross_scope_root_reuse(self):
        configured = audit_registry_json(
            [
                (
                    "proj_scope_a",
                    uuid.UUID("11111111-1111-4111-8111-111111111111"),
                    "zar-a",
                    {"zar-a": TEST_AUDIT_KEY_RAW},
                ),
                (
                    "proj_scope_b",
                    uuid.UUID("22222222-2222-4222-8222-222222222222"),
                    "zar-b",
                    {"zar-b": TEST_AUDIT_KEY_RAW},
                ),
            ]
        )
        with override_settings(ZOOM_REMOVAL_AUDIT_KEYRING_JSON=configured):
            with self.assertRaises(AuditKeyringError) as raised:
                configured_audit_keyrings()
        self.assertEqual(raised.exception.code, "audit_key_conflict")

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
            # The retained v2 vector stays byte-exact, but its static
            # continuous/step_free declaration can no longer create a binding.
            with self.assertRaises(AssertionRejected) as raised:
                verify_deauthorization_assertion(
                    generated,
                    project=SimpleNamespace(object_id=claims["project_id"]),
                    purpose=SETTLE_PURPOSE,
                    received_at=datetime.fromtimestamp(claims["iat"], tz=datetime_timezone.utc),
                )
            self.assertEqual(raised.exception.code, "clock_untrusted")
            v3 = fixture["v3"]
            v3_claims = v3["settlement_claims"]
            generated_v3 = sign_claims(
                v3_claims,
                private_key=Ed25519PrivateKey.from_private_bytes(seed),
                header=fixture["header"],
            )
            self.assertEqual(generated_v3, v3["compact_jws"])
            self.assertEqual(hashlib.sha256(generated_v3.encode("ascii")).hexdigest(), v3["compact_jws_sha256"])
            verified = verify_deauthorization_assertion(
                generated_v3,
                project=SimpleNamespace(object_id=v3_claims["project_id"]),
                purpose=SETTLE_PURPOSE,
                received_at=datetime.fromtimestamp(v3_claims["iat"], tz=datetime_timezone.utc),
            )
        self.assertEqual(verified.claims, v3_claims)
        self.assertEqual(v3_claims["temporal_policy"], TEMPORAL_POLICY)
        self.assertFalse({"client_clock_continuous", "client_clock_step_free"} & set(v3_claims))

    def test_public_v3_temporal_evidence_vector_is_byte_exact(self):
        vector = json.loads(
            (Path(__file__).with_name("fixtures") / "zoom_deauthorization_vectors.json").read_text()
        )["v3"]["temporal_evidence_vector"]
        snapshot = vector["snapshot"]
        self.assertEqual(
            json.dumps([snapshot[name] for name in vector["ordered_fields"]], separators=(",", ":"), ensure_ascii=False),
            vector["canonical_candidate_json"],
        )
        candidate_digest = candidate_temporal_evidence_digest(snapshot)
        self.assertEqual(candidate_digest, vector["candidate_evidence_digest"])
        self.assertEqual(
            binding_temporal_evidence_digest(candidate_digest, vector["event_binding_id"], vector["event_binding_version"]),
            vector["binding_evidence_digest"],
        )

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
    ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE=True,
    ZOOM_DEAUTH_DB_CLOCK_HEALTH_ID="attendee-db-clock-test-v1",
    ZOOM_DEAUTH_DB_CLOCK_ERROR_MS=0,
    ZOOM_DEAUTH_DB_CLOCK_CONTINUOUS=True,
    ZOOM_DEAUTH_CLOCK_SOURCE_POLICY_ID="attendee-src-test",
    ZOOM_DEAUTH_CLOCK_MAX_SAMPLE_ERROR_MS="1000",
    ZOOM_DEAUTH_CLOCK_MAX_RTT_MS="1000",
    LOG_BOT_STATE_CHANGES=False,
)
class ZoomSignedDeauthorizationTests(TransactionTestCase):
    """The v2 static clock settings above are deliberately still set: they
    must not admit anything. Kernel evidence is SYNTHETIC (patched healthy,
    maxerror 0) and the binding sample is a fixed SYNTHETIC value so digests
    are predictable; neither is evidence of live clock readiness."""

    reset_sequences = True

    def setUp(self):
        self.kernel_patch = patch.object(LocalProbe, "kernel", return_value=Kernel(0, 0x2001, 0))
        self.kernel_patch.start()
        self.binding_sample_patch = patch(
            "bots.zoom_deauthorization.sample_database_clock",
            side_effect=lambda: (self.binding_sample, None) if self.binding_sample else (None, "clock_rejected"),
        )
        self.binding_sample_patch.start()
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
        self.zoom_app.legacy_history_unknown = False
        self.zoom_app.authorization_history_baseline_at = database_clock_now()
        self.zoom_app.save(
            update_fields=["legacy_history_unknown", "authorization_history_baseline_at", "updated_at"]
        )
        self.zoom_app.set_credentials({"client_secret": "client-secret-a", "webhook_secret": "webhook-secret-a"})
        self.audit_ring_entries = {
            (self.project.object_id, str(self.zoom_app.deauthorization_binding_id)): {
                "current_kid": TEST_AUDIT_KID,
                "keys": {TEST_AUDIT_KID: TEST_AUDIT_KEY_RAW},
            }
        }
        self.audit_ring_override = None
        self.activate_audit_registry()
        ZoomRemovalAuditKeyFingerprint.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            key_id=TEST_AUDIT_KID,
            key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
        )
        self.private_key = Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_SEED)
        self.signing_keys = {str(self.app_binding): self.private_key}
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
        self.binding_sample = Sample(
            db_at=datetime.fromtimestamp(self.now, tz=datetime_timezone.utc),
            error_ms=0,
            rtt_us=1,
            source_policy_id="attendee-src-test",
        )
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
            identity_audit_key_id=TEST_AUDIT_KID,
            identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
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
            connection_digest=connection_binding_digest(self.connection),
            connection_audit_key_id=TEST_AUDIT_KID,
            connection_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            identity_digest=identity_digest,
            identity_audit_key_id=TEST_AUDIT_KID,
            identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            authorization_generation=self.connection.authorization_generation,
            generation_started_at=datetime.fromtimestamp(self.now - 600, tz=datetime_timezone.utc),
            start_clock_health_id="attendee-db-clock-test-v1",
            start_clock_error_ms=0,
            start_clock_continuous=True,
            legacy_history=False,
        )
        self.add_clock_sample(self.grant, "start")

    def tearDown(self):
        self.registry_override.disable()
        self.audit_ring_override.disable()
        self.binding_sample_patch.stop()
        self.kernel_patch.stop()

    def add_clock_sample(self, grant, boundary, *, error_ms=0, source="attendee-src-test"):
        """SYNTHETIC boundary sample row for fixture grants (never readiness)."""
        return ZoomOAuthAuthorizationGrantClockSample.objects.create(
            authorization_grant=grant,
            boundary=boundary,
            measurement_policy=CLOCK_MEASUREMENT_POLICY,
            source_policy_id=source,
            sampled_at=grant.generation_started_at if boundary == "start" else grant.generation_ended_at,
            error_ms=error_ms,
            rtt_us=1,
        )

    def activate_audit_registry(self):
        if self.audit_ring_override is not None:
            self.audit_ring_override.disable()
        entries = [
            (
                project_id,
                uuid.UUID(app_binding),
                ring["current_kid"],
                ring["keys"],
            )
            for (project_id, app_binding), ring in self.audit_ring_entries.items()
        ]
        self.audit_ring_override = override_settings(
            ZOOM_REMOVAL_AUDIT_KEYRING_JSON=audit_registry_json(entries)
        )
        self.audit_ring_override.enable()

    def add_audit_ring(self, app, *, current_kid=TEST_AUDIT_KID, keys=None):
        keys = keys or {
            current_kid: hashlib.sha256(
                f"audit-ring:{app.project.object_id}:{app.deauthorization_binding_id}".encode("ascii")
            ).digest()
        }
        self.audit_ring_entries[(app.project.object_id, str(app.deauthorization_binding_id))] = {
            "current_kid": current_kid,
            "keys": keys,
        }
        self.activate_audit_registry()
        for kid, raw_key in keys.items():
            ZoomRemovalAuditKeyFingerprint.objects.create(
                project=app.project,
                zoom_oauth_app=app,
                key_id=kid,
                key_fingerprint=key_fingerprint(raw_key),
            )
        return keys

    def add_registry_app(self, app):
        self.add_audit_ring(app)
        registry = json.loads(json.dumps(self.registry))
        audience = f"urn:attendee:test:{self.project.object_id}:{app.deauthorization_binding_id}:zoom-deauthorization"
        private_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(f"signer:{app.deauthorization_binding_id}".encode("ascii")).digest()
        )
        self.signing_keys[str(app.deauthorization_binding_id)] = private_key
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        registry[self.project.object_id][str(app.deauthorization_binding_id)] = {
            "zoom_oauth_app_id": app.pk,
            "expected_client_id_digest": expected_client_id_digest(app.client_id),
            "issuer": TEST_ISSUER,
            "audience": audience,
            "keys": {TEST_KID: b64url(public_key)},
        }
        return registry, audience

    def legacy_app_fixture(self, *, live=True):
        app = ZoomOAuthApp.objects.create(
            project=self.project,
            client_id=f"legacy-client-{uuid.uuid4().hex[:8]}",
        )
        app.set_credentials({"client_secret": "legacy-client-secret", "webhook_secret": "legacy-webhook-secret"})
        connection = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=app,
            user_id="legacy-stable-user",
            account_id="legacy-stable-account",
        )
        connection.set_credentials({"refresh_token": "legacy-refresh-token"})
        # Simulate rows that existed before 0096 installed its INSERT guards.
        # Constraints remain active; only user triggers are bypassed within
        # this test fixture transaction.
        with transaction.atomic():
            with django_db_connection.cursor() as cursor:
                cursor.execute("SET LOCAL session_replication_role = replica")
            lineage = ZoomOAuthAuthorizationLineage.objects.create(
                project=self.project,
                zoom_oauth_app=app,
                identity_digest=hashlib.sha256(uuid.uuid4().bytes + b":legacy-identity").hexdigest(),
                latest_grant_sequence=1,
                has_prior_grant=True,
                history_complete=False,
            )
            grant = ZoomOAuthAuthorizationGrant.objects.create(
                project=self.project,
                zoom_oauth_app=app,
                lineage=lineage,
                grant_sequence=1,
                live_connection=connection if live else None,
                connection_digest=hashlib.sha256(uuid.uuid4().bytes + b":legacy-connection").hexdigest(),
                identity_digest=lineage.identity_digest,
                authorization_generation=connection.authorization_generation,
                generation_started_at=database_clock_now() - timedelta(minutes=5),
                start_clock_health_id="legacy-untrusted",
                start_clock_error_ms=1001,
                start_clock_continuous=False,
                legacy_history=True,
            )
        registry, audience = self.add_registry_app(app)
        return app, connection, lineage, grant, registry, audience

    def replace_grant_fixture(self, *, lineage_overrides=None, start_sample_error_ms=0, **grant_overrides):
        """Build a different immutable history fixture instead of rewriting it."""

        grant_values = {
            "binding_id": self.grant.binding_id,
            "project": self.project,
            "zoom_oauth_app": self.zoom_app,
            "grant_sequence": self.grant.grant_sequence,
            "live_connection": self.connection,
            "connection_digest": self.grant.connection_digest,
            "identity_digest": self.grant.identity_digest,
            "identity_audit_key_id": self.grant.identity_audit_key_id,
            "identity_audit_key_fingerprint": self.grant.identity_audit_key_fingerprint,
            "connection_audit_key_id": self.grant.connection_audit_key_id,
            "connection_audit_key_fingerprint": self.grant.connection_audit_key_fingerprint,
            "authorization_generation": self.grant.authorization_generation,
            "generation_started_at": self.grant.generation_started_at,
            "start_clock_health_id": self.grant.start_clock_health_id,
            "start_clock_error_ms": self.grant.start_clock_error_ms,
            "start_clock_continuous": self.grant.start_clock_continuous,
            "legacy_history": self.grant.legacy_history,
        }
        self.grant.delete()
        if lineage_overrides:
            self.connection.user_id = f"{self.connection.user_id}-replacement-{uuid.uuid4().hex[:8]}"
            self.connection.account_id = f"{self.connection.account_id}-replacement"
            self.connection.save(update_fields=["user_id", "account_id", "updated_at"])
            identity_digest = provider_identity_digest(
                self.project,
                self.zoom_app,
                self.connection.user_id,
                self.connection.account_id,
            )
            lineage_values = {
                "project": self.project,
                "zoom_oauth_app": self.zoom_app,
                "identity_digest": identity_digest,
                "identity_audit_key_id": TEST_AUDIT_KID,
                "identity_audit_key_fingerprint": TEST_AUDIT_KEY_FINGERPRINT,
                "latest_grant_sequence": 1,
                "has_prior_grant": False,
                "history_complete": True,
            }
            lineage_values.update(lineage_overrides)
            self.lineage = ZoomOAuthAuthorizationLineage.objects.create(**lineage_values)
            grant_values["identity_digest"] = identity_digest
            grant_values["identity_audit_key_id"] = TEST_AUDIT_KID
            grant_values["identity_audit_key_fingerprint"] = TEST_AUDIT_KEY_FINGERPRINT
        grant_values["lineage"] = self.lineage
        grant_values.update(grant_overrides)
        self.grant = ZoomOAuthAuthorizationGrant.objects.create(**grant_values)
        if start_sample_error_ms is not None:
            self.add_clock_sample(self.grant, "start", error_ms=start_sample_error_ms)
        if self.grant.generation_ended_at is not None:
            self.add_clock_sample(self.grant, "end", error_ms=start_sample_error_ms or 0)
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
            "zoom_event_id": event_id or opaque_event_id(),
            "zoom_event_at": event_at,
            "zoom_request_signed_at": request_at,
            "first_verified_at": first_at,
            "zoom_event_precision_ms": 1000,
            "zoom_request_precision_ms": 1000,
            "temporal_policy": TEMPORAL_POLICY,
            "clock_measurement_policy": CLOCK_MEASUREMENT_POLICY,
            "client_clock_source_policy_id": "client-src-test",
            "client_receipt_clock_error_ms": 0,
            "client_issuance_clock_error_ms": 0,
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
        samples = {sample.boundary: sample for sample in self.grant.clock_samples.all()}
        snapshot = _candidate_snapshot(
            SimpleNamespace(claims=claims),
            self.grant,
            samples.get("start"),
            samples.get("end"),
            self.binding_sample,
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
        private_key = self.signing_keys.get(claims.get("zoom_oauth_app_binding"), self.private_key)
        return self.client.post(
            path,
            data=json.dumps({"assertion": assertion or sign_claims(claims, private_key=private_key)}),
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
        self.assertEqual(
            response.json()["verified_deauthorization_event_digest"],
            hashlib.sha256(claims["zoom_event_id"].encode("ascii")).hexdigest(),
        )
        self.assertFalse(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
        self.assertFalse(ZoomMeetingToZoomOAuthConnectionMapping.objects.filter(pk=mapping.pk).exists())
        self.assertFalse(WebhookDeliveryAttempt.objects.filter(pk=delivery.pk).exists())
        self.assertEqual(ZoomDeauthorizationEventBinding.objects.count(), 1)
        self.assertEqual(ZoomDeauthorizationAssertionReceipt.objects.count(), 1)
        operation = ZoomRemovalOperation.objects.get()
        receipt = ZoomDeauthorizationAssertionReceipt.objects.get()
        binding = ZoomDeauthorizationEventBinding.objects.get()
        self.assertIsNone(operation.target_object_id)
        self.assertEqual(operation.storage_manifest, {})
        self.assertIsNone(operation.lease_token)
        self.assertIsNone(operation.lease_expires_at)
        self.assertEqual(
            operation.expires_at - operation.completed_at,
            timedelta(days=RECEIPT_RETENTION_DAYS),
        )
        self.assertEqual(
            receipt.expires_at - receipt.received_at,
            timedelta(days=RECEIPT_RETENTION_DAYS),
        )
        durable_safe_evidence = json.dumps(
            {
                "operation": operation_result(operation),
                "binding": binding.evidence_snapshot,
            },
            sort_keys=True,
        )
        revoke.assert_not_called()
        rendered = response.content.decode()
        for marker in (self.connection.user_id, self.connection.account_id, self.connection.object_id, "refresh-marker-A", claims["zoom_event_id"]):
            self.assertNotIn(marker, rendered)
            self.assertNotIn(marker, durable_safe_evidence)

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
        self.assertEqual(
            set(recovery.json()),
            {
                "error",
                "event_binding_id",
                "event_binding_version",
                "temporal_evidence_digest",
            },
        )
        self.assertNotIn(claims["zoom_event_id"], recovery.content.decode())
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

    def test_sampled_bounds_are_frozen_and_retry_uses_exact_snapshot(self):
        self.binding_sample = Sample(
            db_at=self.binding_sample.db_at, error_ms=700, rtt_us=1, source_policy_id="attendee-src-test"
        )
        claims = self.settle_claims()
        claims["client_receipt_clock_error_ms"] = 300
        claims["client_issuance_clock_error_ms"] = 200
        samples = {sample.boundary: sample for sample in self.grant.clock_samples.all()}
        snapshot = _candidate_snapshot(SimpleNamespace(claims=claims), self.grant, samples["start"], None, self.binding_sample)
        claims["temporal_evidence_digest"] = candidate_temporal_evidence_digest(snapshot)
        first = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(first.status_code, 200, first.content)
        binding = ZoomDeauthorizationEventBinding.objects.get()
        self.assertEqual(binding.temporal_policy, TEMPORAL_POLICY)
        frozen = binding.evidence_snapshot
        self.assertEqual(frozen["clock_measurement_policy"], CLOCK_MEASUREMENT_POLICY)
        self.assertEqual(frozen["attendee_binding_clock_error_ms"], 700)
        self.assertEqual(frozen["attendee_boundary_clock_error_ms"], [0, None])
        self.assertEqual(frozen["client_receipt_clock_error_ms"], 300)
        self.assertEqual(frozen["attendee_binding_received_at"], "%s" % self.binding_sample.db_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        self.assertFalse({"client_clock_continuous", "client_clock_step_free", "attendee_receipt_clock_continuous"} & set(frozen))

        # Retry after the source policy disappears and the sampler fails:
        # existing_only recovers the exact frozen binding, never re-samples it.
        self.binding_sample = None
        claims.update(
            {
                "binding_mode": EXISTING_ONLY,
                "jti": str(uuid.uuid4()),
                "client_issuance_clock_error_ms": None,
                "temporal_evidence_digest": binding.binding_evidence_digest,
            }
        )
        with override_settings(ZOOM_DEAUTH_CLOCK_SOURCE_POLICY_ID=""):
            replay = self.post_assertion("/api/v1/zoom_retention/deauthorization", claims)
        self.assertEqual(replay.status_code, 200, replay.content)
        binding.refresh_from_db()
        self.assertEqual(binding.evidence_snapshot, frozen)

    def test_existing_only_resolver_miss_is_target_free_and_never_matches(self):
        claims = self.resolve_claims(mode=EXISTING_ONLY)
        with patch("bots.zoom_deauthorization.find_provider_identity_lineage") as identity_matcher:
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

    def test_four_timestamp_horizon_29_succeeds(self):
        fresh = self.resolve_claims(event_at=self.now - 29, request_at=self.now, first_at=self.now, iat=self.now)
        accepted = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", fresh)
        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.assertEqual(accepted.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.RESOLVED)
        self.assertEqual(ZoomDeauthorizationEventBinding.objects.count(), 1)

    def test_four_timestamp_horizon_30_is_durable_unbound(self):
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
            ("clock_measurement_policy", "continuous-step-free", "clock_untrusted"),
            ("client_receipt_clock_error_ms", 1001, "clock_error_invalid"),
            ("client_issuance_clock_error_ms", None, "clock_error_invalid"),
            ("client_clock_source_policy_id", None, "clock_source_invalid"),
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

    def test_event_id_requires_exact_lowercase_hmac_sha256_shape_without_mutation(self):
        invalid_event_ids = (
            "zev_" + "A" * 64,
            "zev_" + "g" * 64,
            "zev_" + "_" + "a" * 63,
            "zev_" + "a" * 63,
            "zev_" + "a" * 65,
        )
        for event_id in invalid_event_ids:
            with self.subTest(event_id=event_id):
                response = self.post_assertion(
                    "/api/v1/zoom_retention/deauthorization/resolve",
                    self.resolve_claims(event_id=event_id),
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()["error"], "event_id_invalid")
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=self.connection.pk).exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())
        self.assertFalse(ZoomDeauthorizationTargetResolution.objects.exists())
        self.assertFalse(ZoomDeauthorizationAssertionReceipt.objects.exists())

    def _budget_case(self, receipt_error, issuance_error, start_error, binding_error):
        self.replace_grant_fixture(start_sample_error_ms=start_error)
        self.binding_sample = Sample(
            db_at=self.binding_sample.db_at, error_ms=binding_error, rtt_us=1, source_policy_id="attendee-src-test"
        )
        claims = self.resolve_claims()
        claims["client_receipt_clock_error_ms"] = receipt_error
        claims["client_issuance_clock_error_ms"] = issuance_error
        response = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", claims)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["outcome"]

    def test_combined_sampled_budget_boundary(self):
        # max(client receipt, issuance) + max(grant start, grant end, binding) <= 1000
        for case in ((601, 0, 400, 0), (0, 601, 0, 400), (300, 300, 701, 0), (300, 300, 0, 701)):
            with self.subTest(case=case):
                self.assertEqual(self._budget_case(*case), ZoomDeauthorizationResolutionOutcomes.CLOCK_UNTRUSTED)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())
        self.assertEqual(self._budget_case(600, 0, 400, 0), ZoomDeauthorizationResolutionOutcomes.RESOLVED)

    def test_combined_budget_issuance_and_binding_dominant_exact_boundary(self):
        self.assertEqual(self._budget_case(0, 600, 0, 400), ZoomDeauthorizationResolutionOutcomes.RESOLVED)

    def test_historic_or_mismatched_grant_samples_are_never_upgraded(self):
        variants = ("missing", "other_source", "binding_sampler_rejects", "ended_without_end_sample")
        healthy = self.binding_sample
        for variant in variants:
            with self.subTest(variant=variant):
                ZoomDeauthorizationTargetResolution.objects.all().delete()
                self.binding_sample = healthy
                if variant == "missing":
                    # A pre-v3 grant: static v2 columns claim continuity, no sample.
                    self.replace_grant_fixture(start_sample_error_ms=None)
                elif variant == "other_source":
                    self.replace_grant_fixture(start_sample_error_ms=None)
                    self.add_clock_sample(self.grant, "start", source="other-source")
                elif variant == "ended_without_end_sample":
                    # Ended under a static v2 declaration: no end sample exists.
                    self.replace_grant_fixture()
                    ZoomOAuthAuthorizationGrant.objects.filter(pk=self.grant.pk).update(
                        live_connection=None,
                        generation_ended_at=datetime.fromtimestamp(self.now + 120, tz=datetime_timezone.utc),
                        end_clock_health_id="attendee-db-clock-test-v1",
                        end_clock_error_ms=0,
                        end_clock_continuous=True,
                    )
                    self.connection.delete()
                else:
                    self.replace_grant_fixture()
                    self.binding_sample = None
                response = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", self.resolve_claims())
                self.assertEqual(response.status_code, 200, response.content)
                self.assertEqual(response.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.CLOCK_UNTRUSTED)
                self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())

    def test_v2_static_claims_never_create_but_v2_shape_is_recognised(self):
        claims = self.resolve_claims()
        for name in ("clock_measurement_policy", "client_clock_source_policy_id",
                     "client_receipt_clock_error_ms", "client_issuance_clock_error_ms"):
            claims.pop(name)
        claims.update(temporal_policy=TEMPORAL_POLICY_V2, client_clock_health_id="client-db-clock-test-v1",
                      client_clock_continuous=True, client_clock_step_free=True, client_clock_error_ms=0)
        response = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", claims)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "clock_untrusted")
        claims.update(binding_mode=EXISTING_ONLY, jti=str(uuid.uuid4()))
        response = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", claims)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())

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

    def test_unverified_surrogate_signer_selectors_fail_closed_without_mutation(self):
        claims = self.settle_claims()
        surrogate_issuer = dict(claims, iss="unpaired-\ud800")
        cases = (
            (
                sign_claims(surrogate_issuer, private_key=self.private_key),
                "issuer_invalid",
            ),
            (
                sign_claims(
                    claims,
                    private_key=self.private_key,
                    header={"alg": "EdDSA", "kid": "unpaired-\ud800", "typ": ASSERTION_TYP},
                ),
                "unknown_key",
            ),
        )
        before = (
            ZoomOAuthConnection.objects.count(),
            ZoomRemovalOperation.objects.count(),
            ZoomDeauthorizationEventBinding.objects.count(),
            ZoomDeauthorizationTargetResolution.objects.count(),
            ZoomDeauthorizationAssertionReceipt.objects.count(),
        )
        for assertion, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                response = self.post_assertion(
                    "/api/v1/zoom_retention/deauthorization",
                    claims,
                    assertion=assertion,
                )
                self.assertEqual(response.status_code, 401, response.content)
                self.assertEqual(response.json(), {"error": expected_code})
        self.assertEqual(
            before,
            (
                ZoomOAuthConnection.objects.count(),
                ZoomRemovalOperation.objects.count(),
                ZoomDeauthorizationEventBinding.objects.count(),
                ZoomDeauthorizationTargetResolution.objects.count(),
                ZoomDeauthorizationAssertionReceipt.objects.count(),
            ),
        )

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
        expected_event_digest = hashlib.sha256(claims["zoom_event_id"].encode("ascii")).hexdigest()
        self.assertEqual(first.json()["verified_deauthorization_event_digest"], expected_event_digest)
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
            self.assertEqual(
                readback.json()["verified_deauthorization_event_digest"],
                expected_event_digest,
            )
            rendered = readback.content.decode()
            for raw_marker in (
                claims["zoom_event_id"],
                self.connection.user_id,
                self.connection.account_id,
                self.connection.object_id,
            ):
                self.assertNotIn(raw_marker, rendered)

    def test_resolver_supplied_binding_requires_exact_resolution_receipt(self):
        event_id = opaque_event_id()
        resolved = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            self.resolve_claims(event_id=event_id),
        )
        self.assertEqual(resolved.status_code, 200, resolved.content)
        expected_event_digest = hashlib.sha256(event_id.encode("ascii")).hexdigest()
        self.assertEqual(
            set(resolved.json()),
            {
                "app_digest",
                "connection_digest",
                "connection_generation",
                "event_binding_id",
                "event_binding_version",
                "generation_ended_at",
                "generation_started_at",
                "grant_binding_id",
                "grant_history_complete",
                "grant_sequence",
                "operation_id",
                "outcome",
                "resolution_id",
                "temporal_evidence_digest",
                "verified_deauthorization_event_digest",
                "zoom_oauth_app_binding",
            },
        )
        self.assertEqual(
            resolved.json()["verified_deauthorization_event_digest"],
            expected_event_digest,
        )
        operation = ZoomRemovalOperation.objects.get()
        self.assertIsNone(operation.verified_deauthorization_event_digest)
        self.assertIsNone(operation.signed_deauthorization_settled_at)
        pre_settlement_readback = self.client.get(
            f"/api/v1/zoom_retention/operations/{resolved.json()['operation_id']}",
            HTTP_AUTHORIZATION=f"Token {self.api_key}",
        )
        self.assertEqual(pre_settlement_readback.status_code, 200)
        self.assertEqual(
            pre_settlement_readback.json()["verified_deauthorization_event_digest"],
            expected_event_digest,
        )
        self.assertFalse(pre_settlement_readback.json()["evidence"]["signed_deauthorization"])
        self.assertNotIn(event_id, pre_settlement_readback.content.decode())
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
        self.assertEqual(
            accepted.json()["verified_deauthorization_event_digest"],
            expected_event_digest,
        )

    def test_provider_first_and_signed_first_converge_without_second_provider_call(self):
        event_id = opaque_event_id()
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
        expected_event_digest = hashlib.sha256(event_id.encode("ascii")).hexdigest()
        self.assertEqual(
            signed.json()["verified_deauthorization_event_digest"],
            expected_event_digest,
        )
        combined_readback = self.client.get(
            f"/api/v1/zoom_retention/operations/{canonical}",
            HTTP_AUTHORIZATION=f"Token {self.api_key}",
        )
        self.assertEqual(combined_readback.status_code, 200)
        self.assertEqual(
            combined_readback.json()["verified_deauthorization_event_digest"],
            expected_event_digest,
        )
        self.assertTrue(combined_readback.json()["evidence"]["provider_revoke"])
        self.assertTrue(combined_readback.json()["evidence"]["signed_deauthorization"])
        self.assertNotIn(event_id, combined_readback.content.decode())
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
            identity_audit_key_id=TEST_AUDIT_KID,
            identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            latest_grant_sequence=1,
            history_complete=True,
        )
        self.grant = ZoomOAuthAuthorizationGrant.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            lineage=lineage,
            grant_sequence=1,
            live_connection=self.connection,
            connection_digest=connection_binding_digest(self.connection),
            connection_audit_key_id=TEST_AUDIT_KID,
            connection_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            identity_digest=identity,
            identity_audit_key_id=TEST_AUDIT_KID,
            identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            authorization_generation=self.connection.authorization_generation,
            generation_started_at=datetime.fromtimestamp(self.now - 600, tz=datetime_timezone.utc),
            start_clock_health_id="attendee-db-clock-test-v1",
            start_clock_error_ms=0,
            start_clock_continuous=True,
        )
        self.add_clock_sample(self.grant, "start")
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
        event_id = opaque_event_id()
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
            identity_audit_key_id=TEST_AUDIT_KID,
            identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            latest_grant_sequence=1,
            history_complete=True,
        )
        other_grant = ZoomOAuthAuthorizationGrant.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            lineage=other_lineage,
            grant_sequence=1,
            live_connection=other_connection,
            connection_digest=connection_binding_digest(other_connection),
            connection_audit_key_id=TEST_AUDIT_KID,
            connection_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            identity_digest=other_identity,
            identity_audit_key_id=TEST_AUDIT_KID,
            identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
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
        event_id = opaque_event_id()
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
                    identity_audit_key_id=TEST_AUDIT_KID,
                    identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
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
                    connection_audit_key_id=TEST_AUDIT_KID,
                    connection_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
                    identity_digest="7" * 64,
                    identity_audit_key_id=TEST_AUDIT_KID,
                    identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
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
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                with django_db_connection.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE bots_zoomoauthauthorizationgrant
                           SET generation_ended_at = clock_timestamp(),
                               end_clock_health_id = %s,
                               end_clock_error_ms = 0,
                               end_clock_continuous = TRUE
                         WHERE id = %s
                        """,
                        ["attendee-db-clock-test-v1", self.grant.pk],
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

    def test_database_barrier_rejects_complete_keyed_lineage_and_unknown_recovery_outcome(self):
        app, _connection, legacy_lineage, legacy_grant, _registry, _audience = (
            self.legacy_app_fixture()
        )
        ring = configured_audit_keyring(self.project, app)
        # Null provenance is reserved for rows migrated from the pre-0096
        # schema.  New rows cannot masquerade as those inert tombstones.
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomOAuthAuthorizationLineage.objects.create(
                    project=self.project,
                    zoom_oauth_app=app,
                    identity_digest=hashlib.sha256(b"fresh-unkeyed-lineage").hexdigest(),
                    latest_grant_sequence=1,
                    has_prior_grant=True,
                    history_complete=False,
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomOAuthAuthorizationGrant.objects.create(
                    project=self.project,
                    zoom_oauth_app=app,
                    lineage=legacy_lineage,
                    grant_sequence=2,
                    connection_digest=hashlib.sha256(b"fresh-unkeyed-grant").hexdigest(),
                    identity_digest=legacy_lineage.identity_digest,
                    authorization_generation=uuid.uuid4(),
                    generation_started_at=database_clock_now(),
                    start_clock_health_id="legacy-untrusted",
                    start_clock_error_ms=1001,
                    start_clock_continuous=False,
                    legacy_history=True,
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                with django_db_connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO bots_zoomoauthauthorizationlineage
                            (project_id, zoom_oauth_app_id, identity_digest,
                             identity_audit_key_id, identity_audit_key_fingerprint,
                             legacy_predecessor_id, latest_grant_sequence,
                             has_prior_grant, history_complete, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, NULL, 1, FALSE, TRUE,
                                clock_timestamp(), clock_timestamp())
                        """,
                        [
                            self.project.pk,
                            app.pk,
                            hashlib.sha256(b"barrier-direct-sql").hexdigest(),
                            ring.current_kid,
                            ring.key_fingerprints[ring.current_kid],
                        ],
                    )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                with django_db_connection.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE bots_zoomoauthauthorizationgrant
                           SET legacy_recovery_outcome = 'not-a-valid-outcome'
                         WHERE id = %s
                        """,
                        [legacy_grant.pk],
                    )

    def test_live_connection_identity_and_generation_cannot_drift(self):
        original_user = self.connection.user_id
        original_account = self.connection.account_id
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomOAuthConnection.objects.filter(pk=self.connection.pk).update(
                    user_id="drifted-user",
                    account_id="drifted-account",
                    authorization_generation=uuid.uuid4(),
                )

        # Readiness independently catches a preexisting/trigger-bypassed row.
        with transaction.atomic():
            with django_db_connection.cursor() as cursor:
                cursor.execute("SET LOCAL session_replication_role = replica")
                cursor.execute(
                    """
                    UPDATE bots_zoomoauthconnection
                       SET user_id = %s, account_id = %s
                     WHERE id = %s
                    """,
                    ["drifted-user", "drifted-account", self.connection.pk],
                )
        with self.assertRaises(DeauthorizationReadinessError) as raised:
            collect_readiness(project=self.project, app=self.zoom_app)
        self.assertEqual(raised.exception.code, "grant_binding_invalid")

        with transaction.atomic():
            with django_db_connection.cursor() as cursor:
                cursor.execute("SET LOCAL session_replication_role = replica")
                cursor.execute(
                    """
                    UPDATE bots_zoomoauthconnection
                       SET user_id = %s, account_id = %s
                     WHERE id = %s
                    """,
                    [original_user, original_account, self.connection.pk],
                )

    def test_runtime_rejects_validly_keyed_lineage_bound_to_wrong_live_identity(self):
        target = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=self.zoom_app,
            user_id="wrong-live-target",
            account_id="wrong-live-account",
        )
        target.set_credentials({"refresh_token": "wrong-live-refresh"})
        claimed_user = "signed-identity-a"
        claimed_account = "signed-account-a"
        identity_digest = provider_identity_digest(
            self.project,
            self.zoom_app,
            claimed_user,
            claimed_account,
        )
        lineage = ZoomOAuthAuthorizationLineage.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            identity_digest=identity_digest,
            identity_audit_key_id=TEST_AUDIT_KID,
            identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            latest_grant_sequence=1,
            has_prior_grant=False,
            history_complete=True,
        )
        ZoomOAuthAuthorizationGrant.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            lineage=lineage,
            grant_sequence=1,
            live_connection=target,
            connection_digest=connection_binding_digest(target),
            connection_audit_key_id=TEST_AUDIT_KID,
            connection_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            identity_digest=identity_digest,
            identity_audit_key_id=TEST_AUDIT_KID,
            identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            authorization_generation=target.authorization_generation,
            generation_started_at=database_clock_now() - timedelta(minutes=5),
            start_clock_health_id="attendee-db-clock-test-v1",
            start_clock_error_ms=0,
            start_clock_continuous=True,
        )
        with self.assertRaises(DeauthorizationReadinessError) as raised:
            collect_readiness(project=self.project, app=self.zoom_app)
        self.assertEqual(raised.exception.code, "grant_binding_invalid")

        claims = self.resolve_claims()
        claims.update(
            {
                "zoom_user_id": claimed_user,
                "zoom_account_id": claimed_account,
            }
        )
        response = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            claims,
        )
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.json(), {"error": "grant_binding_invalid"})
        self.assertTrue(ZoomOAuthConnection.objects.filter(pk=target.pk).exists())
        self.assertFalse(
            ZoomRemovalOperation.objects.filter(target_object_id=target.object_id).exists()
        )

    def test_schema_readiness_rejects_same_name_noop_trigger_function(self):
        with django_db_connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_get_functiondef('bots_zoomdeauth_lineage_monotone'::regproc)"
            )
            original_definition = cursor.fetchone()[0]
        try:
            with django_db_connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE OR REPLACE FUNCTION bots_zoomdeauth_lineage_monotone()
                    RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN
                        IF TG_OP = 'DELETE' THEN
                            RETURN OLD;
                        END IF;
                        RETURN NEW;
                    END;
                    $$
                    """
                )
            with self.assertRaises(DeauthorizationReadinessError) as raised:
                collect_readiness(project=self.project, app=self.zoom_app)
            self.assertEqual(raised.exception.code, "schema_unavailable")
        finally:
            with django_db_connection.cursor() as cursor:
                cursor.execute(original_definition)
        collect_readiness(project=self.project, app=self.zoom_app)

    def test_audit_key_fingerprint_registry_is_permanent_and_detects_same_kid_replacement(self):
        registered = ZoomRemovalAuditKeyFingerprint.objects.get(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            key_id=TEST_AUDIT_KID,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomRemovalAuditKeyFingerprint.objects.filter(pk=registered.pk).update(
                    key_fingerprint="e" * 64,
                    algorithm="different",
                    derivation_version=2,
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ZoomRemovalAuditKeyFingerprint.objects.filter(pk=registered.pk).delete()
        replacement_key = bytes(range(64, 96))
        replaced = audit_registry_json(
            [
                (
                    self.project.object_id,
                    self.app_binding,
                    TEST_AUDIT_KID,
                    {TEST_AUDIT_KID: replacement_key},
                )
            ]
        )
        with override_settings(ZOOM_REMOVAL_AUDIT_KEYRING_JSON=replaced):
            with self.assertRaises(DeauthorizationReadinessError) as raised:
                collect_readiness(project=self.project, app=self.zoom_app)
            self.assertEqual(raised.exception.code, "audit_key_conflict")
            payload = {
                "zoom_oauth_app_binding": str(self.app_binding),
                "authorization_code": "must-not-exchange-rebound-key",
                "redirect_uri": "https://client-agent.test/callback",
            }
            with patch(
                "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens"
            ) as exchange:
                connection, error = create_zoom_oauth_connection(payload, self.project)
            self.assertIsNone(connection)
            self.assertEqual(
                error,
                {"error": "Zoom authorization lineage could not be recorded safely."},
            )
            exchange.assert_not_called()

    def test_operation_event_digest_consistency_fails_closed_in_app_and_database(self):
        event_id = opaque_event_id()
        resolved = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization/resolve",
            self.resolve_claims(event_id=event_id),
        )
        self.assertEqual(resolved.status_code, 200, resolved.content)
        operation = ZoomRemovalOperation.objects.get()
        expected_event_digest = hashlib.sha256(event_id.encode("ascii")).hexdigest()

        operation.verified_deauthorization_event_digest = "0" * 64
        operation.verified_deauthorization_at = database_clock_now()
        with self.assertRaises(DatabaseVerificationError):
            operation_result(operation)

        operation.verified_deauthorization_event_digest = expected_event_digest
        operation.verified_deauthorization_at = None
        operation.signed_deauthorization_settled_at = database_clock_now()
        with self.assertRaises(DatabaseVerificationError):
            operation_result(operation)

        with self.assertRaises(IntegrityError):
            with transaction.atomic(), django_db_connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE bots_zoomremovaloperation
                       SET verified_deauthorization_event_digest = %s,
                           verified_deauthorization_at = %s
                     WHERE id = %s
                    """,
                    ["0" * 64, database_clock_now(), operation.pk],
                )

        with self.assertRaises(IntegrityError):
            with transaction.atomic(), django_db_connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE bots_zoomremovaloperation
                       SET signed_deauthorization_settled_at = %s,
                           terminal_basis = %s
                     WHERE id = %s
                    """,
                    [database_clock_now(), "signed_zoom_deauthorization", operation.pk],
                )

        operation.refresh_from_db()
        self.assertIsNone(operation.verified_deauthorization_event_digest)
        self.assertIsNone(operation.verified_deauthorization_at)
        self.assertIsNone(operation.signed_deauthorization_settled_at)

        settlement = self.settle_claims(
            event_id=event_id,
            operation_id=uuid.UUID(resolved.json()["operation_id"]),
            mode=EXISTING_ONLY,
        )
        settlement["resolution_id"] = resolved.json()["resolution_id"]
        settlement["temporal_evidence_digest"] = resolved.json()[
            "temporal_evidence_digest"
        ]
        accepted = self.post_assertion(
            "/api/v1/zoom_retention/deauthorization",
            settlement,
        )
        self.assertEqual(accepted.status_code, 200, accepted.content)
        operation.refresh_from_db()
        self.assertIsNotNone(operation.signed_deauthorization_settled_at)

        binding = ZoomDeauthorizationEventBinding.objects.get()
        with self.assertRaises(IntegrityError):
            with transaction.atomic(), django_db_connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE bots_zoomdeauthorizationeventbinding
                       SET operation_id = NULL
                     WHERE id = %s
                    """,
                    [binding.pk],
                )

        other_operation = _get_or_create_operation(
            project=self.project,
            operation_id=uuid.uuid4(),
            operation_type=ZoomRemovalOperationTypes.PURGE_BOT,
            target_object_id="bot_binding_reassignment_test",
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic(), django_db_connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE bots_zoomdeauthorizationeventbinding
                       SET operation_id = %s
                     WHERE id = %s
                    """,
                    [other_operation.pk, binding.pk],
                )

        with self.assertRaises(IntegrityError):
            with transaction.atomic(), django_db_connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM bots_zoomdeauthorizationeventbinding WHERE id = %s",
                    [binding.pk],
                )

        resolution = ZoomDeauthorizationTargetResolution.objects.get()
        resolution.event_digest = "1" * 64
        with self.assertRaises(DeauthorizationServiceError):
            resolution_result(resolution)

        with self.assertRaises(IntegrityError):
            with transaction.atomic(), django_db_connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO bots_zoomdeauthorizationtargetresolution (
                        resolution_id,
                        project_id,
                        zoom_oauth_app_id,
                        event_digest,
                        outcome,
                        event_binding_id,
                        authorization_grant_id,
                        operation_id,
                        grant_binding_id,
                        connection_digest,
                        authorization_generation,
                        binding_evidence_digest,
                        created_at,
                        updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    [
                        uuid.uuid4(),
                        self.project.pk,
                        self.zoom_app.pk,
                        "1" * 64,
                        ZoomDeauthorizationResolutionOutcomes.RESOLVED,
                        binding.pk,
                        self.grant.pk,
                        operation.pk,
                        self.grant.binding_id,
                        self.grant.connection_digest,
                        self.grant.authorization_generation,
                        binding.binding_evidence_digest,
                        database_clock_now(),
                        database_clock_now(),
                    ],
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
        self.assertEqual(
            grants[0].generation_ended_at,
            grants[1].generation_started_at,
        )
        self.assertIsNone(grants[0].live_connection_id)
        self.assertEqual(grants[1].live_connection_id, second.pk)
        grants[0].lineage.refresh_from_db()
        self.assertTrue(grants[0].lineage.has_prior_grant)
        serialized = ZoomOAuthConnectionSerializer(second).data
        self.assertEqual(serialized["zoom_oauth_app_binding"], str(self.app_binding))
        self.assertEqual(serialized["grant_sequence"], 2)
        # Each boundary is the operation-coupled sampled instant itself; the
        # legacy v2 columns carry an explicit non-claim, never continuity.
        first_samples = {sample.boundary: sample for sample in grants[0].clock_samples.all()}
        second_samples = {sample.boundary: sample for sample in grants[1].clock_samples.all()}
        self.assertEqual(set(first_samples), {"start", "end"})
        self.assertEqual(set(second_samples), {"start"})
        self.assertEqual(first_samples["start"].sampled_at, grants[0].generation_started_at)
        self.assertEqual(first_samples["end"].sampled_at, grants[0].generation_ended_at)
        self.assertEqual(second_samples["start"].sampled_at, grants[1].generation_started_at)
        for sample in [*first_samples.values(), *second_samples.values()]:
            self.assertEqual(sample.measurement_policy, CLOCK_MEASUREMENT_POLICY)
            self.assertEqual(sample.source_policy_id, "attendee-src-test")
            self.assertLessEqual(sample.error_ms, 1000)
        for grant in grants:
            self.assertFalse(grant.start_clock_continuous)
            self.assertEqual(grant.start_clock_error_ms, 1001)
        self.assertIs(grants[0].end_clock_continuous, False)

    def test_rejected_boundary_sample_records_grant_without_fresh_evidence(self):
        ZoomOAuthAuthorizationGrant.objects.all().delete()
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
        # SYNTHETIC unsynchronized kernel (STA_UNSYNC) at the boundary.
        with patch.object(LocalProbe, "kernel", return_value=Kernel(0, 0x0041, 0)), patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens", return_value=token
        ), patch("bots.zoom_oauth_connections_api_utils._get_user_info", return_value=user):
            connection, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(error)
        grant = connection.authorization_grant
        self.assertFalse(grant.clock_samples.exists())
        self.connection, self.grant = connection, grant
        claims = self.resolve_claims(iat=self.now + 120, event_at=self.now + 120, request_at=self.now + 120, first_at=self.now + 120)
        self.binding_sample = Sample(
            db_at=datetime.fromtimestamp(self.now + 120, tz=datetime_timezone.utc), error_ms=0, rtt_us=1,
            source_policy_id="attendee-src-test",
        )
        with patch("bots.zoom_retention_api_views.database_clock_now",
                   return_value=datetime.fromtimestamp(self.now + 120, tz=datetime_timezone.utc)):
            response = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", claims)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.CLOCK_UNTRUSTED)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())

    def test_clock_sample_rows_are_boundary_coupled_and_never_updated(self):
        sample = self.grant.clock_samples.get()
        with self.assertRaises(IntegrityError), transaction.atomic():
            ZoomOAuthAuthorizationGrantClockSample.objects.filter(pk=sample.pk).update(error_ms=1)
        with self.assertRaises(IntegrityError), transaction.atomic():
            ZoomOAuthAuthorizationGrantClockSample.objects.create(
                authorization_grant=self.grant, boundary="end", measurement_policy=CLOCK_MEASUREMENT_POLICY,
                source_policy_id="attendee-src-test", sampled_at=self.grant.generation_started_at, error_ms=0, rtt_us=1,
            )
        with self.assertRaises(IntegrityError), transaction.atomic():
            ZoomOAuthAuthorizationGrantClockSample.objects.create(
                authorization_grant=self.grant, boundary="start", measurement_policy="continuous-step-free",
                source_policy_id="attendee-src-test", sampled_at=self.grant.generation_started_at, error_ms=0, rtt_us=1,
            )
        sample.refresh_from_db()
        self.assertEqual(sample.error_ms, 0)

    def test_real_kernel_sample_mechanics_are_not_readiness(self):
        """Real adjtimex(modes=0) and real PostgreSQL on this host: mechanics
        only, under an unapproved test policy; never live readiness."""
        from bots.zoom_deauthorization_grants import sample_database_clock

        self.kernel_patch.stop()
        try:
            real_kernel = LocalProbe().kernel()
            with transaction.atomic():
                measured, code = sample_database_clock()
        finally:
            self.kernel_patch.start()
        if measured is None:
            self.assertIn(code, {"clock_unsynchronized", "clock_local_movement", "clock_bound_excessive",
                                 "clock_bracket_violation", "clock_latency_excessive"})
        else:
            self.assertGreaterEqual(measured.error_ms, -(-real_kernel.maxerror_us // 1000))
            self.assertEqual(measured.source_policy_id, "attendee-src-test")

    def test_rotation_reads_retained_identity_key_and_writes_current_connection_key(self):
        new_kid = "zar-test-current-v2"
        new_raw = bytes(range(64, 96))
        rotated = audit_registry_json(
            [
                (
                    self.project.object_id,
                    self.app_binding,
                    new_kid,
                    {TEST_AUDIT_KID: TEST_AUDIT_KEY_RAW, new_kid: new_raw},
                )
            ]
        )
        ZoomRemovalAuditKeyFingerprint.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            key_id=new_kid,
            key_fingerprint=key_fingerprint(new_raw),
        )
        payload = {
            "zoom_oauth_app_binding": str(self.app_binding),
            "authorization_code": "rotation-code",
            "redirect_uri": "https://client-agent.test/callback",
        }
        token = {
            "access_token": "rotation-access",
            "refresh_token": "rotation-refresh",
            "scope": "user:read:user user:read:zak meeting:read:list_meetings meeting:read:local_recording_token",
        }
        user = {"id": self.connection.user_id, "account_id": self.connection.account_id, "status": "active"}
        original_digest = self.lineage.identity_digest
        with override_settings(ZOOM_REMOVAL_AUDIT_KEYRING_JSON=rotated), patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens", return_value=token
        ), patch("bots.zoom_oauth_connections_api_utils._get_user_info", return_value=user):
            reauthorized, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(error)
        grant = reauthorized.authorization_grant
        self.assertEqual(grant.grant_sequence, 2)
        self.assertEqual(grant.identity_digest, original_digest)
        self.assertEqual(grant.identity_audit_key_id, TEST_AUDIT_KID)
        self.assertEqual(grant.identity_audit_key_fingerprint, TEST_AUDIT_KEY_FINGERPRINT)
        self.assertEqual(grant.connection_audit_key_id, new_kid)
        self.assertEqual(grant.connection_audit_key_fingerprint, key_fingerprint(new_raw))
        self.lineage.refresh_from_db()
        self.assertEqual(self.lineage.identity_digest, original_digest)
        self.assertEqual(self.lineage.identity_audit_key_id, TEST_AUDIT_KID)

    def test_missing_retained_database_kid_fails_before_provider_exchange(self):
        new_kid = "zar-test-current-v2"
        new_raw = bytes(range(64, 96))
        new_only = audit_registry_json(
            [(self.project.object_id, self.app_binding, new_kid, {new_kid: new_raw})]
        )
        ZoomRemovalAuditKeyFingerprint.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            key_id=new_kid,
            key_fingerprint=key_fingerprint(new_raw),
        )
        payload = {
            "zoom_oauth_app_binding": str(self.app_binding),
            "authorization_code": "must-not-exchange",
            "redirect_uri": "https://client-agent.test/callback",
        }
        with override_settings(ZOOM_REMOVAL_AUDIT_KEYRING_JSON=new_only), patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens"
        ) as exchange:
            connection, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(connection)
        self.assertEqual(error, {"error": "Zoom authorization lineage could not be recorded safely."})
        exchange.assert_not_called()

    def test_multi_key_identity_match_is_audit_key_conflict_without_mutation(self):
        new_kid = "zar-test-current-v2"
        new_raw = bytes(range(64, 96))
        rotated = audit_registry_json(
            [
                (
                    self.project.object_id,
                    self.app_binding,
                    new_kid,
                    {TEST_AUDIT_KID: TEST_AUDIT_KEY_RAW, new_kid: new_raw},
                )
            ]
        )
        ZoomRemovalAuditKeyFingerprint.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            key_id=new_kid,
            key_fingerprint=key_fingerprint(new_raw),
        )
        with override_settings(ZOOM_REMOVAL_AUDIT_KEYRING_JSON=rotated):
            new_digest = provider_identity_digest(
                self.project,
                self.zoom_app,
                self.connection.user_id,
                self.connection.account_id,
            )
            ZoomOAuthAuthorizationLineage.objects.create(
                project=self.project,
                zoom_oauth_app=self.zoom_app,
                identity_digest=new_digest,
                identity_audit_key_id=new_kid,
                identity_audit_key_fingerprint=key_fingerprint(new_raw),
                latest_grant_sequence=1,
                has_prior_grant=True,
                history_complete=False,
            )
            response = self.post_assertion(
                "/api/v1/zoom_retention/deauthorization/resolve",
                self.resolve_claims(),
            )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json(), {"error": "audit_key_conflict"})
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.exists())
        self.assertFalse(ZoomRemovalOperation.objects.exists())

    def test_capture_gate_is_independent_default_off_and_pre_provider(self):
        payload = {
            "zoom_oauth_app_binding": str(self.app_binding),
            "authorization_code": "must-not-exchange",
            "redirect_uri": "https://client-agent.test/callback",
        }
        with override_settings(ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE=False), patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens"
        ) as exchange:
            connection, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(connection)
        self.assertEqual(error, {"error": "Zoom authorization lineage could not be recorded safely."})
        exchange.assert_not_called()

    def test_exact_capture_rejects_unnameable_provider_identity_without_mutation(self):
        payload = {
            "zoom_oauth_app_binding": str(self.app_binding),
            "authorization_code": "invalid-provider-identity",
            "redirect_uri": "https://client-agent.test/callback",
        }
        token = {
            "access_token": "invalid-provider-identity-access",
            "refresh_token": "invalid-provider-identity-refresh",
            "scope": (
                "user:read:user user:read:zak meeting:read:list_meetings "
                "meeting:read:local_recording_token"
            ),
        }
        before_connections = ZoomOAuthConnection.objects.count()
        before_lineages = ZoomOAuthAuthorizationLineage.objects.count()
        before_grants = ZoomOAuthAuthorizationGrant.objects.count()
        invalid_identities = (
            ("", "valid-account"),
            ("control\x00user", "valid-account"),
            ("lone-surrogate-\ud800", "valid-account"),
            ("x" * 256, "valid-account"),
            ("valid-user", "control\naccount"),
        )
        for user_id, account_id in invalid_identities:
            with self.subTest(user_id=repr(user_id), account_id=repr(account_id)), patch(
                "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens",
                return_value=token,
            ), patch(
                "bots.zoom_oauth_connections_api_utils._get_user_info",
                return_value={
                    "id": user_id,
                    "account_id": account_id,
                    "status": "active",
                },
            ):
                connection, error = create_zoom_oauth_connection(payload, self.project)
            self.assertIsNone(connection)
            self.assertEqual(error, {"error": "Zoom returned an invalid user identity."})
            self.assertEqual(ZoomOAuthConnection.objects.count(), before_connections)
            self.assertEqual(ZoomOAuthAuthorizationLineage.objects.count(), before_lineages)
            self.assertEqual(ZoomOAuthAuthorizationGrant.objects.count(), before_grants)

    def test_clean_capture_rejects_legacy_callback_before_provider_exchange(self):
        payload = {
            "zoom_oauth_app_id": self.zoom_app.object_id,
            "authorization_code": "legacy-code-must-not-exchange",
            "redirect_uri": "https://client-agent.test/callback",
        }
        with patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens"
        ) as exchange:
            connection, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(connection)
        self.assertEqual(error, {"error": "Exact Zoom OAuth app binding is required."})
        exchange.assert_not_called()

    def test_legacy_callback_rechecks_clean_baseline_after_provider_io(self):
        app = ZoomOAuthApp.objects.create(
            project=self.project,
            client_id=f"baseline-race-{uuid.uuid4().hex[:8]}",
        )
        app.set_credentials(
            {
                "client_secret": "baseline-race-secret",
                "webhook_secret": "baseline-race-webhook",
            }
        )
        payload = {
            "zoom_oauth_app_id": app.object_id,
            "authorization_code": "legacy-race-code",
            "redirect_uri": "https://client-agent.test/callback",
        }
        token = {
            "access_token": "legacy-race-access",
            "refresh_token": "legacy-race-refresh",
            "scope": "",
        }

        def establish_baseline(*_args, **_kwargs):
            app.legacy_history_unknown = False
            app.authorization_history_baseline_at = database_clock_now()
            app.save(
                update_fields=[
                    "legacy_history_unknown",
                    "authorization_history_baseline_at",
                    "updated_at",
                ]
            )
            return token

        with patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens",
            side_effect=establish_baseline,
        ), patch(
            "bots.zoom_oauth_connections_api_utils._get_user_info",
            return_value={
                "id": "legacy-race-user",
                "account_id": "legacy-race-account",
                "status": "active",
            },
        ):
            connection, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(connection)
        self.assertEqual(error, {"error": "Exact Zoom OAuth app binding is required."})
        self.assertFalse(ZoomOAuthConnection.objects.filter(zoom_oauth_app=app).exists())

    def test_backfill_quarantines_live_connection_without_grant_before_marker(self):
        app = ZoomOAuthApp.objects.create(
            project=self.project,
            client_id=f"orphan-client-{uuid.uuid4().hex[:8]}",
        )
        app.set_credentials(
            {"client_secret": "orphan-client-secret", "webhook_secret": "orphan-webhook-secret"}
        )
        orphan = ZoomOAuthConnection.objects.create(
            zoom_oauth_app=app,
            user_id="orphan-live-user",
            account_id="orphan-live-account",
        )
        orphan.set_credentials({"refresh_token": "orphan-refresh"})
        registry, _audience = self.add_registry_app(app)
        with override_settings(ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry):
            with self.assertRaises(DeauthorizationReadinessError) as raised:
                collect_readiness(project=self.project, app=app)
        self.assertEqual(raised.exception.code, "legacy_recovery_incomplete")
        output = StringIO()
        with override_settings(
            ENABLE_ZOOM_RETENTION_REMOVAL_API=False,
            ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE=False,
            ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry,
        ):
            call_command(
                "zoom_deauthorization_backfill_legacy",
                expected_registry_fingerprint=configured_audit_keyrings().fingerprint,
                apply=True,
                stdout=output,
            )
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["orphan_connections_quarantined"], 1)
        orphan.refresh_from_db()
        grant = orphan.authorization_grant
        self.assertTrue(grant.legacy_history)
        self.assertEqual(grant.identity_audit_key_id, TEST_AUDIT_KID)
        self.assertEqual(grant.connection_audit_key_id, TEST_AUDIT_KID)
        self.assertFalse(grant.lineage.history_complete)
        self.assertTrue(grant.lineage.has_prior_grant)
        self.assertFalse(grant.start_clock_continuous)
        app.refresh_from_db()
        self.assertIsNotNone(app.legacy_recovery_completed_at)
        with override_settings(ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry):
            collect_readiness(project=self.project, app=app)

    def test_legacy_remove_reconnect_never_becomes_complete_sequence_one(self):
        app, connection, _legacy_lineage, legacy_grant, registry, audience = self.legacy_app_fixture()
        user_id = connection.user_id
        account_id = connection.account_id
        connection.delete()
        legacy_grant.refresh_from_db()
        self.assertIsNone(legacy_grant.live_connection_id)
        registry_fingerprint = configured_audit_keyrings().fingerprint
        with override_settings(
            ENABLE_ZOOM_RETENTION_REMOVAL_API=False,
            ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE=False,
            ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry,
        ):
            call_command(
                "zoom_deauthorization_backfill_legacy",
                expected_registry_fingerprint=registry_fingerprint,
                apply=True,
            )
        payload = {
            "zoom_oauth_app_binding": str(app.deauthorization_binding_id),
            "authorization_code": "legacy-reconnect-code",
            "redirect_uri": "https://client-agent.test/callback",
        }
        token = {
            "access_token": "legacy-reconnect-access",
            "refresh_token": "legacy-reconnect-refresh",
            "scope": "user:read:user user:read:zak meeting:read:list_meetings meeting:read:local_recording_token",
        }
        user = {"id": user_id, "account_id": account_id, "status": "active"}
        with override_settings(ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry), patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens", return_value=token
        ), patch("bots.zoom_oauth_connections_api_utils._get_user_info", return_value=user):
            reconnected, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(error)
        grant = reconnected.authorization_grant
        self.assertEqual(grant.grant_sequence, 1)
        self.assertTrue(grant.lineage.has_prior_grant)
        self.assertFalse(grant.lineage.history_complete)
        self.assertTrue(grant.legacy_history)

        claims = self.common_claims(purpose=RESOLVE_PURPOSE)
        claims.update(
            {
                "aud": audience,
                "zoom_oauth_app_binding": str(app.deauthorization_binding_id),
                "zoom_client_id": app.client_id,
                "zoom_user_id": user_id,
                "zoom_account_id": account_id,
            }
        )
        with override_settings(ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry):
            response = self.post_assertion("/api/v1/zoom_retention/deauthorization/resolve", claims)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["outcome"], ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_PROVIDER_CLOCK)
        self.assertFalse(ZoomDeauthorizationEventBinding.objects.filter(zoom_oauth_app=app).exists())

    def test_fingerprint_verified_legacy_backfill_links_without_rewriting_then_reconnects_after_quarantine(self):
        app, connection, legacy_lineage, legacy_grant, registry, _audience = self.legacy_app_fixture()
        registry_fingerprint = configured_audit_keyrings().fingerprint
        ring = configured_audit_keyring(self.project, app)
        before_lineage_digest = legacy_lineage.identity_digest
        before_connection_digest = legacy_grant.connection_digest
        with override_settings(ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry):
            with self.assertRaises(DeauthorizationReadinessError) as raised:
                collect_readiness(project=self.project, app=app)
            self.assertEqual(raised.exception.code, "legacy_recovery_incomplete")
            collect_readiness(
                project=self.project,
                app=app,
                require_legacy_recovery=False,
            )
        output = StringIO()
        with override_settings(
            ENABLE_ZOOM_RETENTION_REMOVAL_API=False,
            ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE=False,
            ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry,
        ):
            call_command(
                "zoom_deauthorization_backfill_legacy",
                expected_registry_fingerprint=registry_fingerprint,
                apply=True,
                stdout=output,
            )
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["legacy_successors_created"], 1)
        self.assertEqual(summary["orphan_connections_quarantined"], 1)
        recovered = ZoomOAuthAuthorizationLineage.objects.get(legacy_predecessor=legacy_lineage)
        self.assertEqual(recovered.identity_audit_key_id, TEST_AUDIT_KID)
        self.assertFalse(recovered.history_complete)
        self.assertTrue(recovered.has_prior_grant)
        legacy_lineage.refresh_from_db()
        legacy_grant.refresh_from_db()
        self.assertEqual(legacy_lineage.identity_digest, before_lineage_digest)
        self.assertEqual(legacy_grant.connection_digest, before_connection_digest)
        self.assertIsNone(legacy_lineage.identity_audit_key_id)
        self.assertIsNone(legacy_grant.connection_audit_key_id)
        self.assertIsNone(legacy_grant.live_connection_id)
        self.assertEqual(legacy_grant.legacy_recovery_outcome, "successor_linked")
        app.refresh_from_db()
        self.assertIsNotNone(app.legacy_recovery_completed_at)
        self.assertEqual(app.legacy_recovery_ring_fingerprint, ring.fingerprint)

        payload = {
            "zoom_oauth_app_binding": str(app.deauthorization_binding_id),
            "authorization_code": "post-backfill-code",
            "redirect_uri": "https://client-agent.test/callback",
        }
        token = {
            "access_token": "post-backfill-access",
            "refresh_token": "post-backfill-refresh",
            "scope": "user:read:user user:read:zak meeting:read:list_meetings meeting:read:local_recording_token",
        }
        user = {"id": connection.user_id, "account_id": connection.account_id, "status": "active"}
        with override_settings(ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry), patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens", return_value=token
        ), patch("bots.zoom_oauth_connections_api_utils._get_user_info", return_value=user):
            reconnected, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(error)
        new_grant = reconnected.authorization_grant
        self.assertEqual(new_grant.lineage_id, recovered.pk)
        self.assertEqual(new_grant.grant_sequence, 3)
        self.assertEqual(new_grant.identity_audit_key_id, TEST_AUDIT_KID)
        self.assertEqual(new_grant.connection_audit_key_id, TEST_AUDIT_KID)
        self.assertFalse(new_grant.lineage.history_complete)

    def test_backfill_fingerprint_mismatch_rolls_back_and_lineage_delete_is_forbidden(self):
        _app, _connection, legacy_lineage, _legacy_grant, registry, _audience = self.legacy_app_fixture()
        with override_settings(
            ENABLE_ZOOM_RETENTION_REMOVAL_API=False,
            ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE=False,
            ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=registry,
        ):
            with self.assertRaises(CommandError):
                call_command(
                    "zoom_deauthorization_backfill_legacy",
                    expected_registry_fingerprint="0" * 64,
                    apply=True,
                )
        self.assertFalse(ZoomOAuthAuthorizationLineage.objects.filter(legacy_predecessor=legacy_lineage).exists())
        orphan = ZoomOAuthAuthorizationLineage.objects.create(
            project=self.project,
            zoom_oauth_app=self.zoom_app,
            identity_digest=hashlib.sha256(b"direct-delete-lineage").hexdigest(),
            identity_audit_key_id=TEST_AUDIT_KID,
            identity_audit_key_fingerprint=TEST_AUDIT_KEY_FINGERPRINT,
            has_prior_grant=True,
            history_complete=False,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                with django_db_connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM bots_zoomoauthauthorizationlineage WHERE id = %s",
                        [orphan.pk],
                    )

    def test_readiness_output_is_bounded_and_contains_no_key_material(self):
        report = collect_readiness(project=self.project, app=self.zoom_app)
        rendered = json.dumps(report.safe_dict(), sort_keys=True)
        self.assertIn(report.audit_registry_fingerprint, rendered)
        self.assertIn(TEST_AUDIT_KID, rendered)
        self.assertNotIn(b64url(TEST_AUDIT_KEY_RAW), rendered)
        self.assertNotIn(TEST_AUDIT_KEY_RAW.hex(), rendered)

    def test_surrogate_operator_config_fails_closed_with_bounded_codes(self):
        signer_variants = []
        for field in ("issuer", "audience"):
            configured = json.loads(json.dumps(self.registry))
            configured[self.project.object_id][str(self.app_binding)][field] = "unpaired-\ud800"
            signer_variants.append(configured)
            configured = json.loads(json.dumps(self.registry))
            configured[self.project.object_id][str(self.app_binding)][field] = "format-\u202e"
            signer_variants.append(configured)
        configured = json.loads(json.dumps(self.registry))
        signer = configured[self.project.object_id][str(self.app_binding)]
        signer["keys"] = {"unpaired-\ud800": next(iter(signer["keys"].values()))}
        signer_variants.append(configured)

        for configured in signer_variants:
            with self.subTest(configured=configured), override_settings(
                ZOOM_DEAUTH_TRUSTED_SIGNERS_JSON=configured
            ):
                with self.assertRaises(DeauthorizationReadinessError) as raised:
                    collect_readiness(project=self.project, app=self.zoom_app)
                self.assertEqual(raised.exception.code, "signer_registry_invalid")

        with override_settings(ZOOM_DEAUTH_CLOCK_SOURCE_POLICY_ID="unpaired-\ud800"):
            with self.assertRaises(GrantCaptureUnavailable) as raised:
                configured_clock_policy()
        self.assertEqual(str(raised.exception), "clock_evidence_invalid")

    def test_exact_app_oauth_capture_fails_closed_without_audit_key(self):
        ZoomOAuthAuthorizationGrant.objects.all().delete()
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
        with override_settings(ZOOM_REMOVAL_AUDIT_KEYRING_JSON="{}"), patch(
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
        with CaptureZoomLogBytes() as capture:
            response = self.post_assertion(
                "/api/v1/zoom_retention/deauthorization",
                claims,
                assertion=assertion,
            )
        self.assertEqual(response.status_code, 200)
        signature = assertion.rsplit(".", 1)[1]
        capture.assert_absent(
            self,
            assertion,
            signature,
            claims["zoom_event_id"],
            self.connection.user_id,
            self.connection.account_id,
            self.connection.object_id,
            "refresh-marker-A",
        )
        for marker in (
            assertion,
            signature,
            claims["zoom_event_id"],
            self.connection.user_id,
            self.connection.account_id,
            self.connection.object_id,
            "refresh-marker-A",
        ):
            self.assertNotIn(marker, response.content.decode())

    def test_resolver_readback_and_failed_settlement_logs_are_raw_free(self):
        event_id = opaque_event_id()
        resolve_claims = self.resolve_claims(event_id=event_id)
        resolve_assertion = sign_claims(
            resolve_claims,
            private_key=self.private_key,
        )

        with CaptureZoomLogBytes() as capture:
            resolved = self.post_assertion(
                "/api/v1/zoom_retention/deauthorization/resolve",
                resolve_claims,
                assertion=resolve_assertion,
            )
            self.assertEqual(resolved.status_code, 200, resolved.content)

            readback = self.client.get(
                f"/api/v1/zoom_retention/operations/{resolved.json()['operation_id']}",
                HTTP_AUTHORIZATION=f"Token {self.api_key}",
            )
            self.assertEqual(readback.status_code, 200, readback.content)

            settle_claims = self.settle_claims(
                event_id=event_id,
                operation_id=uuid.UUID(resolved.json()["operation_id"]),
                mode=EXISTING_ONLY,
            )
            settle_claims["temporal_evidence_digest"] = resolved.json()[
                "temporal_evidence_digest"
            ]
            settle_assertion = sign_claims(
                settle_claims,
                private_key=self.private_key,
            )
            failed = self.post_assertion(
                "/api/v1/zoom_retention/deauthorization",
                settle_claims,
                assertion=settle_assertion,
            )

        self.assertEqual(failed.status_code, 409, failed.content)
        self.assertEqual(failed.json()["error"], "resolution_mismatch")
        markers = (
            resolve_assertion,
            resolve_assertion.rsplit(".", 1)[1],
            settle_assertion,
            settle_assertion.rsplit(".", 1)[1],
            event_id,
            self.zoom_app.client_id,
            self.connection.user_id,
            self.connection.account_id,
            self.connection.object_id,
            "refresh-marker-A",
        )
        capture.assert_absent(self, *markers)
        for response in (resolved, readback, failed):
            rendered = response.content.decode()
            for marker in markers:
                self.assertNotIn(marker, rendered)

    def test_unexpected_settlement_failure_middleware_logs_no_request_or_exception(self):
        claims = self.settle_claims()
        assertion = sign_claims(claims, private_key=self.private_key)
        provider_marker = "settlement-provider-exception-body-canary"
        original_raise_request_exception = self.client.raise_request_exception
        self.client.raise_request_exception = False
        try:
            with override_settings(DEBUG=False), CaptureConfiguredZoomLogBytes() as capture, patch(
                "bots.zoom_retention_api_views.settle_verified_deauthorization",
                side_effect=RuntimeError(provider_marker),
            ):
                response = self.post_assertion(
                    "/api/v1/zoom_retention/deauthorization",
                    claims,
                    assertion=assertion,
                )
        finally:
            self.client.raise_request_exception = original_raise_request_exception

        self.assertEqual(response.status_code, 500)
        markers = (
            provider_marker,
            assertion,
            assertion.rsplit(".", 1)[1],
            claims["zoom_event_id"],
            self.connection.user_id,
            self.connection.account_id,
            self.connection.object_id,
            "refresh-marker-A",
        )
        capture.assert_absent(self, *markers)
        for marker in markers:
            self.assertNotIn(marker, response.content.decode())

    def test_oauth_callback_and_worker_failures_log_only_bounded_codes(self):
        authorization_marker = "authorization-code-log-canary"
        provider_marker = "provider-exception-log-canary"
        payload = {
            "zoom_oauth_app_binding": str(self.app_binding),
            "authorization_code": authorization_marker,
            "redirect_uri": "https://client-agent.test/callback-log-canary",
        }
        with CaptureZoomLogBytes() as callback_logs, patch(
            "bots.zoom_oauth_connections_api_utils._exchange_access_code_for_tokens",
            side_effect=RuntimeError(provider_marker),
        ):
            connection, error = create_zoom_oauth_connection(payload, self.project)
        self.assertIsNone(connection)
        self.assertIsNotNone(error)
        callback_logs.assert_absent(
            self,
            authorization_marker,
            provider_marker,
            payload["redirect_uri"],
            self.zoom_app.client_id,
        )
        self.assertIn(b"code=token_exchange_failed", callback_logs.bytes)

        with CaptureZoomLogBytes() as worker_logs, patch(
            "bots.tasks.refresh_zoom_oauth_connection_task._get_access_token",
            side_effect=RuntimeError(provider_marker),
        ):
            with self.assertRaises(Exception):
                refresh_zoom_oauth_connection(self.connection.pk)
        worker_logs.assert_absent(
            self,
            provider_marker,
            self.connection.object_id,
            self.connection.user_id,
            self.connection.account_id,
            "refresh-marker-A",
        )
        self.assertIn(b"code=provider_or_internal_error", worker_logs.bytes)

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
        with CaptureZoomLogBytes() as webhook_logs:
            response = self.client.post(
                f"/external_webhooks/zoom/oauth_apps/{self.zoom_app.object_id}",
                data=body,
                content_type="application/json",
                HTTP_X_ZM_SIGNATURE=signature,
                HTTP_X_ZM_REQUEST_TIMESTAMP=timestamp,
            )
        self.assertEqual(response.status_code, 200)
        webhook_logs.assert_absent(
            self,
            body,
            meeting_marker,
            host_marker,
            operator_marker,
            self.zoom_app.object_id,
            signature,
        )
        self.assertIn(b"event_type=meeting.created", webhook_logs.bytes)

        provider_error = "provider-error-body-log-canary"
        signature_marker = "v0=signature-log-canary"
        query_marker = "authorization-code-query-canary"
        failed_body = json.dumps({"event": "other", "error": provider_error})
        with CaptureZoomLogBytes() as rejected_logs:
            rejected = self.client.post(
                f"/external_webhooks/zoom/oauth_apps/{self.zoom_app.object_id}?code={query_marker}",
                data=failed_body,
                content_type="application/json",
                HTTP_X_ZM_SIGNATURE=signature_marker,
                HTTP_X_ZM_REQUEST_TIMESTAMP=timestamp,
            )
        self.assertEqual(rejected.status_code, 400)
        rejected_logs.assert_absent(
            self,
            failed_body,
            provider_error,
            signature_marker,
            query_marker,
            self.zoom_app.object_id,
        )
        self.assertIn(b"code=invalid_signature", rejected_logs.bytes)


class ZoomDeauthorizationAuditKeyringMigrationTests(TransactionTestCase):
    """Exercise the populated 0095 -> 0096 transition on PostgreSQL."""

    migrate_from = [("bots", "0095_zoom_deauth_operation_event_digest_consistency")]
    migrate_to = [("bots", "0096_zoom_deauth_audit_keyring_readiness")]

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_from)
        self.old_apps = executor.loader.project_state(self.migrate_from).apps

    def tearDown(self):
        executor = MigrationExecutor(django_db_connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
        super().tearDown()

    def _old_scope(self):
        Project = self.old_apps.get_model("bots", "Project")
        ZoomOAuthApp = self.old_apps.get_model("bots", "ZoomOAuthApp")
        organization = Organization.objects.create(name="0096 populated migration")
        project = Project.objects.create(
            organization_id=organization.pk,
            name="0096 project",
            object_id="proj_0096_migration",
        )
        app = ZoomOAuthApp.objects.create(
            project_id=project.pk,
            object_id="zoa_0096_migrate",
            client_id="migration-client",
            deauthorization_binding_id=uuid.UUID(
                "96969696-9696-4969-8969-969696969696"
            ),
        )
        return organization, project, app

    def test_populated_0095_history_is_quarantined_and_permanence_installed(self):
        _organization, project, app = self._old_scope()
        Connection = self.old_apps.get_model("bots", "ZoomOAuthConnection")
        Lineage = self.old_apps.get_model("bots", "ZoomOAuthAuthorizationLineage")
        Grant = self.old_apps.get_model("bots", "ZoomOAuthAuthorizationGrant")
        generation = uuid.UUID("97979797-9797-4979-8979-979797979797")
        live_connection = Connection.objects.create(
            zoom_oauth_app_id=app.pk,
            object_id="zoc_0096_live",
            user_id="migration-live-user",
            account_id="migration-live-account",
            authorization_generation=generation,
        )
        Connection.objects.create(
            zoom_oauth_app_id=app.pk,
            object_id="zoc_0096_orphan",
            user_id="migration-orphan-user",
            account_id="migration-orphan-account",
        )
        live_lineage = Lineage.objects.create(
            project_id=project.pk,
            zoom_oauth_app_id=app.pk,
            identity_digest="1" * 64,
            latest_grant_sequence=1,
            has_prior_grant=False,
            history_complete=True,
        )
        Grant.objects.create(
            project_id=project.pk,
            zoom_oauth_app_id=app.pk,
            lineage_id=live_lineage.pk,
            grant_sequence=1,
            live_connection_id=live_connection.pk,
            connection_digest="2" * 64,
            identity_digest=live_lineage.identity_digest,
            authorization_generation=generation,
            generation_started_at=datetime.now(tz=datetime_timezone.utc)
            - timedelta(minutes=10),
            start_clock_health_id="pre-0096-clock",
            start_clock_error_ms=0,
            start_clock_continuous=True,
            legacy_history=False,
        )
        tombstone = Lineage.objects.create(
            project_id=project.pk,
            zoom_oauth_app_id=app.pk,
            identity_digest="3" * 64,
            latest_grant_sequence=0,
            has_prior_grant=False,
            history_complete=True,
        )

        executor = MigrationExecutor(django_db_connection)
        executor.migrate(self.migrate_to)
        new_apps = executor.loader.project_state(self.migrate_to).apps
        NewApp = new_apps.get_model("bots", "ZoomOAuthApp")
        NewLineage = new_apps.get_model("bots", "ZoomOAuthAuthorizationLineage")
        NewGrant = new_apps.get_model("bots", "ZoomOAuthAuthorizationGrant")
        migrated_app = NewApp.objects.get(pk=app.pk)
        self.assertTrue(migrated_app.legacy_history_unknown)
        self.assertIsNone(migrated_app.authorization_history_baseline_at)
        self.assertIsNone(migrated_app.legacy_recovery_completed_at)
        self.assertTrue(
            all(
                lineage.identity_audit_key_id is None
                and lineage.identity_audit_key_fingerprint is None
                and not lineage.history_complete
                and lineage.has_prior_grant
                for lineage in NewLineage.objects.filter(zoom_oauth_app_id=app.pk)
            )
        )
        migrated_grant = NewGrant.objects.get(lineage_id=live_lineage.pk)
        self.assertTrue(migrated_grant.legacy_history)
        self.assertIsNone(migrated_grant.identity_audit_key_id)
        self.assertEqual(migrated_grant.live_connection_id, live_connection.pk)

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                with django_db_connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM bots_zoomoauthauthorizationlineage WHERE id = %s",
                        [tombstone.pk],
                    )

    def test_scope_conflict_rolls_back_entire_0096_migration(self):
        organization, project, app = self._old_scope()
        Project = self.old_apps.get_model("bots", "Project")
        Lineage = self.old_apps.get_model("bots", "ZoomOAuthAuthorizationLineage")
        other_project = Project.objects.create(
            organization_id=organization.pk,
            name="0096 conflicting project",
            object_id="proj_0096_conflict",
        )
        with transaction.atomic():
            with django_db_connection.cursor() as cursor:
                cursor.execute("SET LOCAL session_replication_role = replica")
                corrupt = Lineage.objects.create(
                    project_id=other_project.pk,
                    zoom_oauth_app_id=app.pk,
                    identity_digest="4" * 64,
                    latest_grant_sequence=0,
                    has_prior_grant=False,
                    history_complete=True,
                )

        executor = MigrationExecutor(django_db_connection)
        with self.assertRaisesRegex(
            RuntimeError,
            "zoom_deauthorization_history_preflight_failed",
        ):
            executor.migrate(self.migrate_to)
        with django_db_connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                      FROM information_schema.columns
                     WHERE table_schema = current_schema()
                       AND table_name = 'bots_zoomoauthauthorizationlineage'
                       AND column_name = 'identity_audit_key_id'
                )
                """
            )
            self.assertFalse(cursor.fetchone()[0])
        self.assertFalse(
            MigrationRecorder(django_db_connection).migration_qs.filter(
                app="bots",
                name="0096_zoom_deauth_audit_keyring_readiness",
            ).exists()
        )

        with transaction.atomic():
            with django_db_connection.cursor() as cursor:
                cursor.execute("SET LOCAL session_replication_role = replica")
                cursor.execute(
                    """
                    UPDATE bots_zoomoauthauthorizationlineage
                       SET project_id = %s
                     WHERE id = %s
                    """,
                    [project.pk, corrupt.pk],
                )
        MigrationExecutor(django_db_connection).migrate(self.migrate_to)
