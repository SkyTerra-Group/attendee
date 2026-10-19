"""DB-backed readiness checks for the signed Zoom deauthorization boundary."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import unicodedata
import uuid
from dataclasses import dataclass

from django.conf import settings
from django.db import connection
from django.db.migrations.recorder import MigrationRecorder
from django.urls import NoReverseMatch, reverse

from bots.models import (
    Project,
    ZoomOAuthApp,
    ZoomOAuthAuthorizationGrant,
    ZoomRemovalAuditKeyFingerprint,
)
from bots.zoom_deauthorization_assertion import _registry
from bots.zoom_deauthorization_grants import GrantCaptureUnavailable, configured_clock_evidence, expected_client_id_digest
from bots.zoom_removal_audit import (
    AUDIT_KEY_ALGORITHM,
    AUDIT_KEY_DERIVATION_DOMAIN,
    AUDIT_KEY_DERIVATION_VERSION,
    AuditKeyringError,
    configured_audit_keyrings,
    digest_with_key,
)


class DeauthorizationReadinessError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SIGNER_FIELDS = {"zoom_oauth_app_id", "expected_client_id_digest", "issuer", "audience", "keys"}
_REQUIRED_ROUTES = (
    "zoom-retention-deauthorization",
    "zoom-retention-deauthorization-resolve",
    "zoom-retention-operation-detail",
)
_REQUIRED_MIGRATIONS = {
    "0094_zoom_deauthorization_trust",
    "0095_zoom_deauth_operation_event_digest_consistency",
    "0096_zoom_deauth_audit_keyring_readiness",
}
# (tgtype, function, SHA-256(prosrc), constraint, deferrable,
# initially-deferred, UPDATE-OF columns).  This prevents an enabled same-name
# no-op or INSERT/UPDATE-only replacement from satisfying readiness.
_REQUIRED_TRIGGERS = {
    ("bots_zoomdeauthorizationassertionreceipt", "zoom_deauth_receipt_immutable"): (19, "bots_zoomdeauth_receipt_immutable", "c7f939d9c8727dcb57775a0972751dea9877a614ff10a6eef6378be9b46531b5", False, False, False, ()),
    ("bots_zoomdeauthorizationassertionreceipt", "zoom_deauth_receipt_scoped_links"): (23, "bots_zoomdeauth_receipt_scope", "bc609c744eed19e734e5502b21eef9d4f31dc6137aebf7f8631a30cc1dd78d4f", False, False, False, ()),
    ("bots_zoomdeauthorizationeventbinding", "zoom_deauth_binding_event_digest_consistency"): (23, "bots_zoomdeauth_operation_event_digest_consistent", "02a47bb4c9a3761e012a519d4c47822aca622cf6c18a6ad72f836143658bc66f", False, False, False, ("operation_id", "event_digest")),
    ("bots_zoomdeauthorizationeventbinding", "zoom_deauth_event_binding_delete_forbidden"): (11, "bots_zoomdeauth_event_binding_delete_forbidden", "dbea12129e83deca52307f10f153e7232555489fcb5fdc68f1a536017ca67774", False, False, False, ()),
    ("bots_zoomdeauthorizationeventbinding", "zoom_deauth_event_binding_immutable"): (19, "bots_zoomdeauth_event_binding_immutable", "d8c2ae9cfe19856e171f639547417cfdd3c653bd021b2e19f88c8b90a3af9582", False, False, False, ()),
    ("bots_zoomdeauthorizationeventbinding", "zoom_deauth_event_scoped_links"): (23, "bots_zoomdeauth_scoped_links", "33016e64f421492a2548036b9d9907f90439b2efd49cac3383e4769fdd50fadd", False, False, False, ()),
    ("bots_zoomdeauthorizationeventbinding", "zoom_deauth_old_operation_retains_event_binding"): (25, "bots_zoomdeauth_old_operation_retains_event_binding", "5027452705bb9bcd6e1bb38eed8f6cd776bf82bf1f440e17325e5ace783c02e0", True, True, True, ()),
    ("bots_zoomdeauthorizationtargetresolution", "zoom_deauth_resolution_event_digest_consistency"): (23, "bots_zoomdeauth_operation_event_digest_consistent", "02a47bb4c9a3761e012a519d4c47822aca622cf6c18a6ad72f836143658bc66f", False, False, False, ("event_binding_id", "event_digest")),
    ("bots_zoomdeauthorizationtargetresolution", "zoom_deauth_resolution_monotone"): (19, "bots_zoomdeauth_resolution_monotone", "8b34115712633a4d24b7252b19fedc391de4e3d47b3218e7ed251a30a05f3bc8", False, False, False, ()),
    ("bots_zoomdeauthorizationtargetresolution", "zoom_deauth_resolution_scoped_links"): (23, "bots_zoomdeauth_scoped_links", "33016e64f421492a2548036b9d9907f90439b2efd49cac3383e4769fdd50fadd", False, False, False, ()),
    ("bots_zoomoauthapp", "zoom_deauth_app_binding_immutable"): (23, "bots_zoomdeauth_immutable_app", "6f0efa9f8af2165c4f141b3437b7a6669807173e1ab44d27f2b284e8c9b2c5ad", False, False, False, ()),
    ("bots_zoomoauthauthorizationgrant", "zoom_deauth_grant_invariants"): (23, "bots_zoomdeauth_grant_invariants", "fe5bce3950ad1eb36198d69c6947a18cb8267321034de71d2aeed45eef265226", False, False, False, ()),
    ("bots_zoomoauthauthorizationlineage", "zoom_deauth_lineage_monotone"): (31, "bots_zoomdeauth_lineage_monotone", "b35232c5d3300527e56c71d95a710ba64305ed0c33bda5e71dbba77bdc9124d8", False, False, False, ()),
    ("bots_zoomoauthconnection", "zoom_deauth_connection_live_binding"): (19, "bots_zoomdeauth_connection_live_binding", "51291b2aec84da4d31d51903f401fdfdb1ce2f17fbddaeca529271b31dfc3135", False, False, False, ("zoom_oauth_app_id", "object_id", "user_id", "account_id", "authorization_generation")),
    ("bots_zoomremovalauditkeyfingerprint", "zoom_audit_key_fingerprint_immutable"): (31, "bots_zoomdeauth_audit_key_fingerprint_immutable", "a7439fae159f84258e6592f38c0608df8df814f72e7d22b9092f2c1206b2aa1f", False, False, False, ()),
    ("bots_zoomremovaloperation", "zoom_deauth_operation_event_digest_consistency"): (23, "bots_zoomdeauth_operation_event_digest_consistent", "02a47bb4c9a3761e012a519d4c47822aca622cf6c18a6ad72f836143658bc66f", False, False, False, ("verified_deauthorization_event_digest", "verified_deauthorization_at", "signed_deauthorization_settled_at")),
    ("bots_zoomremovaloperation", "zoom_deauth_operation_monotone"): (19, "bots_zoomdeauth_operation_monotone", "8cb46defcaa440ebb1be44d8851b5ee5d9642c5591e3e4390882350502db9cd1", False, False, False, ()),
    ("bots_zoomremovaloperation", "zoom_deauth_operation_scoped_links"): (23, "bots_zoomdeauth_scoped_links", "33016e64f421492a2548036b9d9907f90439b2efd49cac3383e4769fdd50fadd", False, False, False, ()),
    ("bots_zoomremovaloperation", "zoom_operation_requires_canonical"): (21, "bots_zoomremovaloperation_require_canonical", "39c0a5d10a15a98cc42dd5c7d196e490552fa226a6845906b63942e63dc320c7", True, True, True, ()),
    ("bots_zoomremovaloperationidentifier", "zoom_identifier_preserves_canonical"): (29, "bots_zoomremovaloperation_require_canonical", "39c0a5d10a15a98cc42dd5c7d196e490552fa226a6845906b63942e63dc320c7", True, True, True, ()),
    ("bots_zoomremovaloperationidentifier", "zoom_identifier_project_matches_operation"): (23, "bots_zoomremovalidentifier_enforce_project", "023668154a591f3072d13283da060780bc9b82a61c9db554b36fbfad40d0a70a", False, False, False, ()),
    ("bots_zoomremovaloperationidentifier", "zoom_operation_identifier_immutable"): (19, "bots_zoomoperationidentifier_immutable", "11c6c4f6513370a16d054c9da908357275d71b165c110d6d4d820793645b2b2d", False, False, False, ()),
}

# (constraint type, SHA-256(pg_get_constraintdef)).  Names are scoped to the
# exact table so a same-name object elsewhere cannot satisfy readiness.
_REQUIRED_CONSTRAINTS = {
    ("bots_zoomdeauthorizationassertionreceipt", "unique_zoom_deauth_assertion_nonce"): ("u", "56266d47702665247f7fcef4f032bc5b9713fb7499e770961393a133bbe8026b"),
    ("bots_zoomdeauthorizationassertionreceipt", "zoom_assertion_receipt_target_matches_purpose"): ("c", "9d14917e5691bbb90fa57767b13c389c86942952d3eea7873e929e4fac96fdac"),
    ("bots_zoomdeauthorizationeventbinding", "unique_zoom_deauthorization_event_binding"): ("u", "ca4ec0bede9e7b7495c96324b83143140ecdfd804c50ca45fe0a5db546c4aa50"),
    ("bots_zoomdeauthorizationeventbinding", "zoom_event_binding_terminal_evidence_complete"): ("c", "c84bbce90d7ba5539566c1e32ce67d0dc710ed2e519987d7e5e619a8498d60e1"),
    ("bots_zoomdeauthorizationeventbinding", "zoom_event_binding_version_positive"): ("c", "7ee3c8c0bc3bc1448c413d68cce82e740bff22a3d43fe5e211071ffba983cec6"),
    ("bots_zoomdeauthorizationtargetresolution", "unique_zoom_deauthorization_resolution"): ("u", "ca4ec0bede9e7b7495c96324b83143140ecdfd804c50ca45fe0a5db546c4aa50"),
    ("bots_zoomdeauthorizationtargetresolution", "zoom_deauth_resolution_target_shape"): ("c", "a43d30a93bc3fa65547282731303e1cd3ca3248faa70106a341c6f9c323b3ce9"),
    ("bots_zoomoauthapp", "zoom_app_history_baseline_shape"): ("c", "3af5c99869464ee52523e76ae55a8168b80b510d48bdc218434fd040ccf8882a"),
    ("bots_zoomoauthapp", "zoom_app_legacy_recovery_marker_shape"): ("c", "f02394d7a5694f9c4386c501a65c0314bcba10928bcee220e60b60072f40f58f"),
    ("bots_zoomoauthauthorizationgrant", "unique_zoom_authorization_grant_binding"): ("u", "2677e066285449bf10819352a00a2dcd11f61842fbdd76891a8fe96110896d46"),
    ("bots_zoomoauthauthorizationgrant", "unique_zoom_grant_lineage_sequence"): ("u", "827799e14c7d79da717cdd4e28fc5cfee48af2e0cb260c41260e61683369ff2f"),
    ("bots_zoomoauthauthorizationgrant", "zoom_grant_audit_key_ids_complete"): ("c", "320c701a4cd408eb94b7e9e7b3af71e83e47a2dedbfa7112e7971884f6f8e431"),
    ("bots_zoomoauthauthorizationgrant", "zoom_grant_end_evidence_complete"): ("c", "da8ca184d3480f88a73676d533c6de391ec36c5954c795b88f4169d64353fba7"),
    ("bots_zoomoauthauthorizationgrant", "zoom_grant_interval_ordered"): ("c", "6cd2e892aa58d61c122363e8674c20bea1173619414701f80477eb10fe623737"),
    ("bots_zoomoauthauthorizationgrant", "zoom_grant_live_connection_is_open"): ("c", "bc357b36c180bfe8f9242f9dc0c2b97e37e4cb7e7fd1965a8780fdeb99772109"),
    ("bots_zoomoauthauthorizationgrant", "zoom_grant_legacy_recovery_outcome_valid"): ("c", "3baa0ba3f563a67acefd75f25fb5dff579c59a93226b1c78405bf58f14700507"),
    ("bots_zoomoauthauthorizationgrant", "zoom_grant_sequence_positive"): ("c", "0944e5e62a748286764b434efcd1ed1af0c31edc283b95b4aa92ac84100b9d03"),
    ("bots_zoomoauthauthorizationlineage", "unique_zoom_oauth_authorization_lineage"): ("u", "83a04f0b9f68ab1e9a725768fcd3a255c0bcc113846d6a86b973720ff62124ed"),
    ("bots_zoomoauthauthorizationlineage", "zoom_lineage_sequence_nonnegative"): ("c", "d8c6f5f7cbe52cc9be0031a524cf414f6872f1c4f2d428dac583c9c32d5bfd5a"),
    ("bots_zoomoauthauthorizationlineage", "zoom_lineage_unkeyed_is_incomplete"): ("c", "3e7d66004af536b4f345274921557b886703806466c5df67fcac637c0cb39860"),
    ("bots_zoomremovalauditkeyfingerprint", "zoom_audit_key_registry_fingerprint_unique"): ("u", "da166e215670ca111c43275cf595aee47433982c84cb440ab0b5b89dab0f0d11"),
    ("bots_zoomremovalauditkeyfingerprint", "zoom_audit_key_registry_scope_kid_unique"): ("u", "66f13071cb7183783ca545157128632c285ce28fbc081d26d8ed826ed0af9288"),
    ("bots_zoomremovaloperation", "zoom_removal_signed_event_evidence_complete"): ("c", "a6a9b06d1a378b2b3a544da97de79fa843c05f38d4740423641379f36d1bc740"),
    ("bots_zoomremovaloperation", "zoom_removal_terminal_basis_matches_evidence"): ("c", "17b46ab17d5723a33339650b37131e23ba7ce76a4fe8b30752eb5e9c70df2b63"),
    ("bots_zoomremovaloperationidentifier", "unique_zoom_operation_identifier_namespace"): ("u", "24f5ada0f84505ef8d84d8a8da81a844bb4b803bb9142876bfd4546f2e8ab307"),
}

_REQUIRED_INDEXES = {
    ("bots_zoomdeauthorizationeventbinding", "unique_zoom_deauthorization_binding_operation"): "7aa4a3f6b7a41f2693bb60aa5b831b03a86eacdb24ff5bc6514cf4b53cb3be9d",
    ("bots_zoomremovaloperation", "unique_zoom_purge_target_per_project"): "adbf56558da1faa3a1afb4621ba2cd569840f1c8d0b90e1bd3b33a06db4bd766",
    ("bots_zoomremovaloperation", "unique_zoom_revoke_authorization_grant"): "9e16e5efd2d7d1675b16fb292510718020a7c392e8c2fc043417f4707d6d942b",
    ("bots_zoomremovaloperation", "unique_zoom_revoke_target_generation"): "2c83ed7a9da1d446f129a3a76c77441ea0509a34365dc72a9feedfd913db5e04",
    ("bots_zoomremovaloperation", "unique_zoom_verified_deauth_event"): "da6e64f482a64bb24615e528e9da950322418f8ea05b638a143a760c9b0249fc",
}


@dataclass(frozen=True)
class ReadyAuditRing:
    project_object_id: str
    app_binding: str
    ring_fingerprint: str
    current_kid: str
    retained_kids: tuple[str, ...]


@dataclass(frozen=True)
class ReadinessReport:
    audit_registry_fingerprint: str
    audit_rings: tuple[ReadyAuditRing, ...]
    signer_key_fingerprints: tuple[tuple[str, str, str, str], ...]
    app_count: int
    legacy_barrier_app_count: int
    inert_legacy_lineage_count: int
    inert_legacy_grant_count: int
    attendee_clock_error_budget_ms: int | None
    removal_route_enabled: bool
    grant_capture_enabled: bool

    def safe_dict(self) -> dict:
        return {
            "ready": True,
            "audit_registry_fingerprint": self.audit_registry_fingerprint,
            "audit_rings": [
                {
                    "project_id": ring.project_object_id,
                    "app_binding": ring.app_binding,
                    "ring_fingerprint": ring.ring_fingerprint,
                    "current_kid": ring.current_kid,
                    "retained_kids": list(ring.retained_kids),
                }
                for ring in self.audit_rings
            ],
            "signer_key_fingerprints": [
                {
                    "project_id": project_id,
                    "app_binding": binding,
                    "kid": kid,
                    "public_key_fingerprint": fingerprint,
                }
                for project_id, binding, kid, fingerprint in self.signer_key_fingerprints
            ],
            "app_count": self.app_count,
            "legacy_barrier_app_count": self.legacy_barrier_app_count,
            "inert_legacy_lineage_count": self.inert_legacy_lineage_count,
            "inert_legacy_grant_count": self.inert_legacy_grant_count,
            "attendee_clock_error_budget_ms": self.attendee_clock_error_budget_ms,
            "removal_route_enabled": self.removal_route_enabled,
            "grant_capture_enabled": self.grant_capture_enabled,
        }


def _fail(code: str):
    raise DeauthorizationReadinessError(code)


def _valid_utf8_string(value, *, maximum: int, pattern=None) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        len(encoded) <= maximum
        and not any(unicodedata.category(character).startswith("C") for character in value)
        and (pattern is None or pattern.fullmatch(value) is not None)
    )


def _canonical_public_key(encoded) -> bytes:
    if type(encoded) is not str or not encoded or "=" in encoded or not _B64URL_RE.fullmatch(encoded):
        _fail("signer_registry_invalid")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, binascii.Error):
        _fail("signer_registry_invalid")
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded:
        _fail("signer_registry_invalid")
    return raw


def _validate_routes() -> None:
    try:
        reverse(_REQUIRED_ROUTES[0])
        reverse(_REQUIRED_ROUTES[1])
        reverse(_REQUIRED_ROUTES[2], kwargs={"operation_id": uuid.uuid4()})
    except NoReverseMatch:
        _fail("route_unavailable")


def _validate_schema() -> None:
    applied = set(
        MigrationRecorder.Migration.objects.filter(app="bots", name__in=_REQUIRED_MIGRATIONS).values_list(
            "name", flat=True
        )
    )
    if applied != _REQUIRED_MIGRATIONS or connection.vendor != "postgresql":
        _fail("schema_unavailable")
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT relation.relname,
                   trigger.tgname,
                   trigger.tgtype,
                   trigger.tgenabled,
                   procedure.proname,
                   procedure.prosrc,
                   trigger.tgconstraint <> 0,
                   trigger.tgdeferrable,
                   trigger.tginitdeferred,
                   COALESCE((
                       SELECT array_agg(attribute.attname ORDER BY selected.ordinality)
                         FROM unnest(trigger.tgattr::smallint[])
                              WITH ORDINALITY selected(attnum, ordinality)
                         JOIN pg_attribute attribute
                           ON attribute.attrelid = trigger.tgrelid
                          AND attribute.attnum = selected.attnum
                   ), ARRAY[]::name[])
              FROM pg_trigger trigger
              JOIN pg_class relation ON relation.oid = trigger.tgrelid
              JOIN pg_proc procedure ON procedure.oid = trigger.tgfoid
              JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = current_schema() AND NOT trigger.tgisinternal
            """
        )
        trigger_rows = {}
        for table, trigger, tgtype, enabled, function, source, is_constraint, deferred, initially_deferred, columns in cursor.fetchall():
            trigger_rows[(table, trigger)] = (
                tgtype,
                function,
                hashlib.sha256(source.encode("utf-8")).hexdigest(),
                is_constraint,
                deferred,
                initially_deferred,
                tuple(columns),
                enabled,
            )
        cursor.execute(
            """
            SELECT relation.relname,
                   constraint_row.conname,
                   constraint_row.contype,
                   constraint_row.convalidated,
                   pg_get_constraintdef(constraint_row.oid)
              FROM pg_constraint constraint_row
              JOIN pg_class relation ON relation.oid = constraint_row.conrelid
              JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = current_schema()
            """
        )
        constraint_rows = {
            (table, name): (kind, hashlib.sha256(definition.encode("utf-8")).hexdigest(), validated)
            for table, name, kind, validated, definition in cursor.fetchall()
        }
        cursor.execute(
            """
            SELECT table_row.relname,
                   index_row.relname,
                   index_meta.indisunique,
                   index_meta.indisvalid,
                   index_meta.indisready,
                   replace(
                       pg_get_indexdef(index_row.oid),
                       ' ON ' || current_schema() || '.',
                       ' ON <schema>.'
                   )
              FROM pg_index index_meta
              JOIN pg_class index_row ON index_row.oid = index_meta.indexrelid
              JOIN pg_class table_row ON table_row.oid = index_meta.indrelid
              JOIN pg_namespace namespace ON namespace.oid = table_row.relnamespace
             WHERE namespace.nspname = current_schema()
            """
        )
        index_rows = {
            (table, name): (
                unique,
                valid,
                ready,
                hashlib.sha256(definition.encode("utf-8")).hexdigest(),
            )
            for table, name, unique, valid, ready, definition in cursor.fetchall()
        }
    if any(
        trigger_rows.get(trigger) != (*expected, "O")
        for trigger, expected in _REQUIRED_TRIGGERS.items()
    ):
        _fail("schema_unavailable")
    if any(
        constraint_rows.get(constraint) != (*expected, True)
        for constraint, expected in _REQUIRED_CONSTRAINTS.items()
    ):
        _fail("schema_unavailable")
    if any(
        index_rows.get(index) != (True, True, True, expected_hash)
        for index, expected_hash in _REQUIRED_INDEXES.items()
    ):
        _fail("schema_unavailable")


def _selected_rings(registry, *, project: Project | None, app: ZoomOAuthApp | None):
    if app is not None:
        if project is None or app.project_id != project.pk:
            _fail("app_binding_mismatch")
        try:
            return (registry.select(project.object_id, app.deauthorization_binding_id),)
        except AuditKeyringError as error:
            _fail(error.code)
    if project is not None:
        rings = tuple(ring for ring in registry.rings if ring.project_object_id == project.object_id)
        if not rings:
            _fail("audit_key_unavailable")
        return rings
    return registry.rings


def _validate_signers(*, rings, enforce_cross_project_separation: bool):
    try:
        signer_registry = _registry()
    except Exception:
        _fail("signer_registry_invalid")
    if type(signer_registry) is not dict:
        _fail("signer_registry_invalid")

    fingerprints = []
    separation_values = {"issuer": {}, "audience": {}, "public_key": {}}
    if enforce_cross_project_separation:
        configured_scopes = set()
        for project_id, project_registry in signer_registry.items():
            if (
                not _valid_utf8_string(project_id, maximum=32, pattern=_SAFE_ID_RE)
                or type(project_registry) is not dict
                or not project_registry
            ):
                _fail("signer_registry_invalid")
            for binding, signer in project_registry.items():
                try:
                    parsed_binding = uuid.UUID(binding)
                except (ValueError, TypeError, AttributeError):
                    _fail("signer_registry_invalid")
                if str(parsed_binding) != binding or parsed_binding.version != 4 or type(signer) is not dict:
                    _fail("signer_registry_invalid")
                configured_scopes.add((project_id, binding))
        ring_scopes = {(ring.project_object_id, ring.app_binding) for ring in rings}
        if configured_scopes != ring_scopes:
            _fail("signer_registry_invalid")

    for ring in rings:
        project = Project.objects.filter(object_id=ring.project_object_id).first()
        if project is None:
            _fail("app_binding_mismatch")
        project_registry = signer_registry.get(project.object_id)
        if type(project_registry) is not dict:
            _fail("signer_registry_invalid")
        signer = project_registry.get(ring.app_binding)
        if type(signer) is not dict or set(signer) != _SIGNER_FIELDS:
            _fail("signer_registry_invalid")
        app = ZoomOAuthApp.objects.filter(
            pk=signer.get("zoom_oauth_app_id"),
            project=project,
            deauthorization_binding_id=ring.app_binding,
        ).first()
        if app is None:
            _fail("app_binding_mismatch")
        if signer.get("expected_client_id_digest") != expected_client_id_digest(app.client_id):
            _fail("client_id_mismatch")
        for field in ("issuer", "audience"):
            value = signer.get(field)
            if (
                not _valid_utf8_string(value, maximum=512)
            ):
                _fail("signer_registry_invalid")
            scope = (project.object_id, ring.app_binding)
            separation_scope = project.object_id if field == "issuer" else scope
            prior_scope = separation_values[field].setdefault(value, separation_scope)
            if enforce_cross_project_separation and prior_scope != separation_scope:
                _fail("environment_separation_invalid")
        keys = signer.get("keys")
        if type(keys) is not dict or not keys:
            _fail("signer_registry_invalid")
        for kid, encoded in keys.items():
            if (
                not _valid_utf8_string(kid, maximum=128, pattern=_SAFE_ID_RE)
            ):
                _fail("signer_registry_invalid")
            fingerprint = hashlib.sha256(_canonical_public_key(encoded)).hexdigest()
            scope = (project.object_id, ring.app_binding)
            prior_scope = separation_values["public_key"].setdefault(fingerprint, scope)
            if enforce_cross_project_separation and prior_scope != scope:
                _fail("environment_separation_invalid")
            fingerprints.append((project.object_id, ring.app_binding, kid, fingerprint))
    return tuple(sorted(fingerprints))


def _validate_app_audit_state(
    ring,
    *,
    clock,
    require_registered_keys: bool,
    require_legacy_recovery: bool,
    scan_persisted_state: bool,
    in_flight_connection_id: int | None,
):
    project = Project.objects.filter(object_id=ring.project_object_id).first()
    app = ZoomOAuthApp.objects.filter(
        project=project,
        deauthorization_binding_id=ring.app_binding,
    ).first()
    if project is None or app is None:
        _fail("app_binding_mismatch")
    configured_fingerprints = ring.key_fingerprints
    registered_fingerprints = {}
    for registered in ZoomRemovalAuditKeyFingerprint.objects.filter(
        project=project,
        zoom_oauth_app=app,
    ):
        if (
            registered.algorithm != AUDIT_KEY_ALGORITHM
            or registered.derivation_domain != AUDIT_KEY_DERIVATION_DOMAIN
            or registered.derivation_version != AUDIT_KEY_DERIVATION_VERSION
        ):
            _fail("audit_key_conflict")
        registered_fingerprints[registered.key_id] = registered.key_fingerprint
    for kid, fingerprint in configured_fingerprints.items():
        registered = registered_fingerprints.get(kid)
        if registered is None and require_registered_keys:
            _fail("audit_key_unavailable")
        if registered is not None and registered != fingerprint:
            _fail("audit_key_conflict")

    if app.legacy_history_unknown != (app.authorization_history_baseline_at is None):
        _fail("legacy_history_unprotected")
    if app.legacy_history_unknown and require_legacy_recovery:
        if (
            app.legacy_recovery_completed_at is None
            or not _HEX64_RE.fullmatch(app.legacy_recovery_ring_fingerprint or "")
        ):
            _fail("legacy_recovery_incomplete")
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT key_id, key_fingerprint
              FROM (
                    SELECT identity_audit_key_id AS key_id,
                           identity_audit_key_fingerprint AS key_fingerprint
                      FROM bots_zoomoauthauthorizationlineage
                     WHERE project_id = %s AND zoom_oauth_app_id = %s
                    UNION
                    SELECT identity_audit_key_id, identity_audit_key_fingerprint
                      FROM bots_zoomoauthauthorizationgrant
                     WHERE project_id = %s AND zoom_oauth_app_id = %s
                    UNION
                    SELECT connection_audit_key_id, connection_audit_key_fingerprint
                      FROM bots_zoomoauthauthorizationgrant
                     WHERE project_id = %s AND zoom_oauth_app_id = %s
                   ) referenced
             WHERE key_id IS NOT NULL
            """,
            [project.pk, app.pk, project.pk, app.pk, project.pk, app.pk],
        )
        referenced = set(cursor.fetchall())
        cursor.execute(
            """
            SELECT
                count(*) FILTER (WHERE lineage.identity_audit_key_id IS NULL),
                bool_or(
                    (lineage.identity_audit_key_id IS NULL AND (
                        lineage.identity_audit_key_fingerprint IS NOT NULL
                        OR lineage.history_complete
                        OR NOT lineage.has_prior_grant
                    ))
                    OR (lineage.identity_audit_key_id IS NOT NULL
                        AND lineage.identity_audit_key_fingerprint IS NULL)
                )
              FROM bots_zoomoauthauthorizationlineage lineage
             WHERE lineage.project_id = %s AND lineage.zoom_oauth_app_id = %s
            """,
            [project.pk, app.pk],
        )
        inert_lineage_count, invalid_lineage = cursor.fetchone()
        cursor.execute(
            """
            SELECT
                count(*) FILTER (WHERE grant_row.identity_audit_key_id IS NULL),
                bool_or(
                    grant_row.identity_digest IS DISTINCT FROM lineage.identity_digest
                    OR grant_row.identity_audit_key_id IS DISTINCT FROM lineage.identity_audit_key_id
                    OR grant_row.identity_audit_key_fingerprint
                       IS DISTINCT FROM lineage.identity_audit_key_fingerprint
                    OR (grant_row.identity_audit_key_id IS NULL AND (
                        grant_row.identity_audit_key_fingerprint IS NOT NULL
                        OR grant_row.connection_audit_key_id IS NOT NULL
                        OR grant_row.connection_audit_key_fingerprint IS NOT NULL
                        OR NOT grant_row.legacy_history
                    ))
                    OR (grant_row.identity_audit_key_id IS NOT NULL AND (
                        grant_row.connection_audit_key_id IS NULL
                        OR grant_row.connection_audit_key_fingerprint IS NULL
                        OR grant_row.legacy_recovery_outcome IS NOT NULL
                    ))
                ),
                bool_or(
                    grant_row.identity_audit_key_id IS NULL AND (
                        grant_row.live_connection_id IS NOT NULL
                        OR grant_row.generation_ended_at IS NULL
                        OR grant_row.legacy_recovery_outcome IS NULL
                        OR (grant_row.legacy_recovery_outcome = 'successor_linked' AND NOT EXISTS (
                            SELECT 1
                              FROM bots_zoomoauthauthorizationlineage successor
                             WHERE successor.legacy_predecessor_id = lineage.id
                        ))
                    )
                )
              FROM bots_zoomoauthauthorizationgrant grant_row
              JOIN bots_zoomoauthauthorizationlineage lineage ON lineage.id = grant_row.lineage_id
             WHERE grant_row.project_id = %s AND grant_row.zoom_oauth_app_id = %s
            """,
            [project.pk, app.pk],
        )
        inert_grant_count, invalid_grant, incomplete_recovery = cursor.fetchone()
        cursor.execute(
            """
            SELECT EXISTS (
                SELECT 1
                  FROM bots_zoomoauthconnection connection_row
             LEFT JOIN bots_zoomoauthauthorizationgrant grant_row
                    ON grant_row.live_connection_id = connection_row.id
                 WHERE connection_row.zoom_oauth_app_id = %s
                   AND (CAST(%s AS bigint) IS NULL OR connection_row.id <> %s)
                   AND grant_row.id IS NULL
            )
            """,
            [app.pk, in_flight_connection_id, in_flight_connection_id],
        )
        orphan_connection = cursor.fetchone()[0]
        cursor.execute(
            """
            SELECT grant_row.identity_digest,
                   grant_row.identity_audit_key_id,
                   grant_row.identity_audit_key_fingerprint,
                   grant_row.connection_digest,
                   grant_row.connection_audit_key_id,
                   grant_row.connection_audit_key_fingerprint,
                   grant_row.authorization_generation,
                   connection_row.object_id,
                   connection_row.user_id,
                   connection_row.account_id,
                   connection_row.authorization_generation,
                   connection_row.zoom_oauth_app_id
              FROM bots_zoomoauthauthorizationgrant grant_row
              JOIN bots_zoomoauthconnection connection_row
                ON connection_row.id = grant_row.live_connection_id
             WHERE grant_row.project_id = %s
               AND grant_row.zoom_oauth_app_id = %s
               AND grant_row.identity_audit_key_id IS NOT NULL
            """,
            [project.pk, app.pk],
        )
        live_grant_bindings = cursor.fetchall()

    if invalid_lineage or invalid_grant or (
        (inert_lineage_count or inert_grant_count) and not app.legacy_history_unknown
    ):
        _fail("legacy_history_unprotected")
    if require_legacy_recovery and (incomplete_recovery or orphan_connection):
        _fail("legacy_recovery_incomplete")
    for kid, fingerprint in referenced:
        configured = configured_fingerprints.get(kid)
        registered = registered_fingerprints.get(kid)
        if configured is None or (registered is None and require_registered_keys):
            _fail("audit_key_unavailable")
        if fingerprint != configured or (registered is not None and fingerprint != registered):
            _fail("audit_key_conflict")

    # Recompute both opaque bindings from the current live connection.  The
    # database trigger prevents later identity/generation drift; this scan
    # also catches pre-migration or trigger-bypassed rows before any signed
    # resolver/settlement can select the wrong live target.
    ring_keys = dict(ring.keys)
    for (
        identity_digest,
        identity_kid,
        identity_fingerprint,
        connection_digest,
        connection_kid,
        connection_fingerprint,
        grant_generation,
        connection_object_id,
        user_id,
        account_id,
        connection_generation,
        connection_app_id,
    ) in live_grant_bindings:
        if connection_app_id != app.pk or connection_generation != grant_generation:
            _fail("grant_binding_invalid")
        identity_matches = [
            kid
            for kid, raw_key in ring_keys.items()
            if hmac.compare_digest(
                digest_with_key(
                    raw_key,
                    "zoom-provider-identity-v1",
                    project.object_id,
                    str(app.deauthorization_binding_id),
                    user_id,
                    account_id,
                ),
                identity_digest,
            )
        ]
        connection_matches = [
            kid
            for kid, raw_key in ring_keys.items()
            if hmac.compare_digest(
                digest_with_key(
                    raw_key,
                    "zoom-connection-v1",
                    project.object_id,
                    str(app.deauthorization_binding_id),
                    connection_object_id,
                ),
                connection_digest,
            )
        ]
        if (
            identity_matches != [identity_kid]
            or connection_matches != [connection_kid]
            or identity_fingerprint != configured_fingerprints.get(identity_kid)
            or connection_fingerprint != configured_fingerprints.get(connection_kid)
        ):
            _fail("grant_binding_invalid")

    attendee_budget = clock.error_ms if clock is not None else None
    if clock is not None and scan_persisted_state:
        eligible_grants = ZoomOAuthAuthorizationGrant.objects.filter(
            project=project,
            zoom_oauth_app=app,
            lineage__history_complete=True,
            lineage__has_prior_grant=False,
            lineage__latest_grant_sequence=1,
            grant_sequence=1,
            legacy_history=False,
        )
        for grant in eligible_grants:
            evidence = [(grant.start_clock_health_id, grant.start_clock_error_ms, grant.start_clock_continuous)]
            if grant.generation_ended_at is not None:
                evidence.append((grant.end_clock_health_id, grant.end_clock_error_ms, grant.end_clock_continuous))
            for health_id, error_ms, continuous in evidence:
                if health_id != clock.health_id or type(error_ms) is not int or continuous is not True:
                    _fail("clock_untrusted")
                attendee_budget = max(attendee_budget, error_ms)
            if attendee_budget > 1000:
                _fail("clock_untrusted")

    return app, inert_lineage_count, inert_grant_count, attendee_budget


def collect_readiness(
    *,
    project: Project | None = None,
    app: ZoomOAuthApp | None = None,
    require_trusted_clock: bool = True,
    require_registered_keys: bool = True,
    require_legacy_recovery: bool = True,
    scan_persisted_state: bool = True,
    in_flight_connection_id: int | None = None,
) -> ReadinessReport:
    try:
        registry = configured_audit_keyrings()
    except AuditKeyringError as error:
        _fail(error.code)
    clock = None
    if require_trusted_clock:
        try:
            clock = configured_clock_evidence()
        except GrantCaptureUnavailable:
            _fail("clock_untrusted")
    _validate_schema()
    _validate_routes()
    rings = _selected_rings(registry, project=project, app=app)
    fingerprints = _validate_signers(
        rings=rings,
        enforce_cross_project_separation=project is None and app is None,
    )
    apps = []
    barrier_count = 0
    inert_lineage_count = 0
    inert_grant_count = 0
    attendee_budget = clock.error_ms if clock is not None else None
    for ring in rings:
        ready_app, lineages, grants, app_budget = _validate_app_audit_state(
            ring,
            clock=clock,
            require_registered_keys=require_registered_keys,
            require_legacy_recovery=require_legacy_recovery,
            scan_persisted_state=scan_persisted_state,
            in_flight_connection_id=in_flight_connection_id,
        )
        apps.append(ready_app)
        barrier_count += int(ready_app.legacy_history_unknown)
        inert_lineage_count += lineages
        inert_grant_count += grants
        if app_budget is not None:
            attendee_budget = app_budget if attendee_budget is None else max(attendee_budget, app_budget)
    safe_rings = tuple(
        ReadyAuditRing(
            project_object_id=ring.project_object_id,
            app_binding=ring.app_binding,
            ring_fingerprint=ring.fingerprint,
            current_kid=ring.current_kid,
            retained_kids=ring.kids,
        )
        for ring in rings
    )
    return ReadinessReport(
        audit_registry_fingerprint=registry.fingerprint,
        audit_rings=safe_rings,
        signer_key_fingerprints=fingerprints,
        app_count=len(apps),
        legacy_barrier_app_count=barrier_count,
        inert_legacy_lineage_count=inert_lineage_count,
        inert_legacy_grant_count=inert_grant_count,
        attendee_clock_error_budget_ms=attendee_budget,
        removal_route_enabled=settings.ENABLE_ZOOM_RETENTION_REMOVAL_API,
        grant_capture_enabled=settings.ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE,
    )


def assert_capture_ready(
    app: ZoomOAuthApp,
    *,
    in_flight_connection=None,
) -> ReadinessReport:
    if not settings.ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE:
        _fail("grant_capture_disabled")
    if in_flight_connection is not None and in_flight_connection.zoom_oauth_app_id != app.pk:
        _fail("app_binding_mismatch")
    return collect_readiness(
        project=app.project,
        app=app,
        in_flight_connection_id=(
            in_flight_connection.pk if in_flight_connection is not None else None
        ),
    )


def assert_signed_app_ready(app: ZoomOAuthApp) -> ReadinessReport:
    if not settings.ENABLE_ZOOM_RETENTION_REMOVAL_API:
        _fail("removal_api_disabled")
    # Existing immutable bindings remain recoverable across a later clock
    # epoch failure. New binding paths validate current clock evidence inside
    # ``_fresh_binding_evidence``.
    return collect_readiness(
        project=app.project,
        app=app,
        require_trusted_clock=False,
        scan_persisted_state=False,
    )
