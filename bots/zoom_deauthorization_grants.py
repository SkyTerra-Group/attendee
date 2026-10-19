"""Immutable Zoom authorization lineage capture for signed deauthorization."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db import connection as database_connection

from bots.models import (
    Project,
    ZoomOAuthApp,
    ZoomOAuthAuthorizationGrant,
    ZoomOAuthAuthorizationLineage,
    ZoomOAuthConnection,
    ZoomRemovalAuditKeyFingerprint,
)
from bots.zoom_removal_audit import (
    AUDIT_KEY_ALGORITHM,
    AUDIT_KEY_DERIVATION_DOMAIN,
    AUDIT_KEY_DERIVATION_VERSION,
    AuditKeyringError,
    configured_audit_keyring,
    digest_with_key,
)


class GrantCaptureUnavailable(Exception):
    pass


@dataclass(frozen=True)
class ClockEvidence:
    health_id: str
    error_ms: int
    continuous: bool


@dataclass(frozen=True)
class GrantReplacementBoundary:
    at: datetime
    clock: ClockEvidence


_CLOCK_HEALTH_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")


def valid_provider_identity_component(value) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= 255 and not any(
        unicodedata.category(character).startswith("C")
        for character in value
    )


def database_clock_now():
    with database_connection.cursor() as cursor:
        cursor.execute("SELECT clock_timestamp()")
        return cursor.fetchone()[0]


def configured_clock_evidence() -> ClockEvidence:
    health_id = settings.ZOOM_DEAUTH_DB_CLOCK_HEALTH_ID
    error_ms = settings.ZOOM_DEAUTH_DB_CLOCK_ERROR_MS
    continuous = settings.ZOOM_DEAUTH_DB_CLOCK_CONTINUOUS
    try:
        encoded_health_id = health_id.encode("utf-8") if type(health_id) is str else b""
    except UnicodeEncodeError:
        raise GrantCaptureUnavailable("clock_evidence_invalid") from None
    if (
        not encoded_health_id
        or len(encoded_health_id) > 64
        or not _CLOCK_HEALTH_ID_RE.fullmatch(health_id)
        or type(error_ms) is not int
        or error_ms < 0
        or error_ms > 1000
        or continuous is not True
    ):
        raise GrantCaptureUnavailable("clock_evidence_invalid")
    return ClockEvidence(health_id=health_id, error_ms=error_ms, continuous=continuous)


def provider_identity_digest(project: Project, zoom_app: ZoomOAuthApp, user_id: str, account_id: str) -> str:
    """Return the current-writer digest (tests/backfill should also retain its kid)."""

    try:
        ring = configured_audit_keyring(project, zoom_app)
    except AuditKeyringError as error:
        raise GrantCaptureUnavailable(error.code) from None
    return digest_with_key(
        ring.current_key,
        "zoom-provider-identity-v1",
        project.object_id,
        str(zoom_app.deauthorization_binding_id),
        user_id,
        account_id,
    )


def provider_identity_candidates(project: Project, zoom_app: ZoomOAuthApp, user_id: str, account_id: str) -> tuple[tuple[str, str], ...]:
    try:
        ring = configured_audit_keyring(project, zoom_app)
    except AuditKeyringError as error:
        raise GrantCaptureUnavailable(error.code) from None
    return tuple(
        (
            kid,
            digest_with_key(
                raw_key,
                "zoom-provider-identity-v1",
                project.object_id,
                str(zoom_app.deauthorization_binding_id),
                user_id,
                account_id,
            ),
        )
        for kid, raw_key in ring.keys
    )


def connection_binding_digest(connection: ZoomOAuthConnection) -> str:
    ring, candidates = connection_binding_candidates(connection)
    return dict(candidates)[ring.current_kid]


def connection_binding_candidates(connection: ZoomOAuthConnection):
    try:
        ring = configured_audit_keyring(connection.zoom_oauth_app.project, connection.zoom_oauth_app)
    except AuditKeyringError as error:
        raise GrantCaptureUnavailable(error.code) from None
    return ring, tuple(
        (
            kid,
            digest_with_key(
                raw_key,
                "zoom-connection-v1",
                connection.zoom_oauth_app.project.object_id,
                str(connection.zoom_oauth_app.deauthorization_binding_id),
                connection.object_id,
            ),
        )
        for kid, raw_key in ring.keys
    )


def expected_client_id_digest(client_id: str) -> str:
    return hashlib.sha256(client_id.encode("utf-8")).hexdigest()


def grant_binding_digest(binding_id) -> str:
    return hashlib.sha256(str(binding_id).encode("ascii")).hexdigest()


def _require_retained_database_keys(zoom_app: ZoomOAuthApp, ring) -> None:
    configured_fingerprints = ring.key_fingerprints
    registered_fingerprints = {}
    for registered in ZoomRemovalAuditKeyFingerprint.objects.filter(
        project=zoom_app.project,
        zoom_oauth_app=zoom_app,
    ):
        if (
            registered.algorithm != AUDIT_KEY_ALGORITHM
            or registered.derivation_domain != AUDIT_KEY_DERIVATION_DOMAIN
            or registered.derivation_version != AUDIT_KEY_DERIVATION_VERSION
        ):
            raise GrantCaptureUnavailable("audit_key_conflict")
        registered_fingerprints[registered.key_id] = registered.key_fingerprint
    for kid, fingerprint in configured_fingerprints.items():
        registered = registered_fingerprints.get(kid)
        if registered is None:
            raise GrantCaptureUnavailable("audit_key_unavailable")
        if registered != fingerprint:
            raise GrantCaptureUnavailable("audit_key_conflict")

    referenced = set(
        ZoomOAuthAuthorizationLineage.objects.filter(zoom_oauth_app=zoom_app)
        .exclude(identity_audit_key_id__isnull=True)
        .values_list("identity_audit_key_id", "identity_audit_key_fingerprint")
    )
    referenced.update(
        ZoomOAuthAuthorizationGrant.objects.filter(zoom_oauth_app=zoom_app)
        .exclude(identity_audit_key_id__isnull=True)
        .values_list("identity_audit_key_id", "identity_audit_key_fingerprint")
    )
    referenced.update(
        ZoomOAuthAuthorizationGrant.objects.filter(zoom_oauth_app=zoom_app)
        .exclude(connection_audit_key_id__isnull=True)
        .values_list("connection_audit_key_id", "connection_audit_key_fingerprint")
    )
    for kid, fingerprint in referenced:
        configured = configured_fingerprints.get(kid)
        registered = registered_fingerprints.get(kid)
        if configured is None or registered is None:
            raise GrantCaptureUnavailable("audit_key_unavailable")
        if fingerprint != configured or fingerprint != registered:
            raise GrantCaptureUnavailable("audit_key_conflict")


def find_provider_identity_lineage(
    project: Project,
    zoom_app: ZoomOAuthApp,
    user_id: str,
    account_id: str,
    *,
    for_update: bool = False,
) -> tuple[ZoomOAuthAuthorizationLineage | None, tuple[tuple[str, str], ...]]:
    """Resolve one identity across every retained key, never by current only."""

    try:
        ring = configured_audit_keyring(project, zoom_app)
    except AuditKeyringError as error:
        raise GrantCaptureUnavailable(error.code) from None
    candidates = provider_identity_candidates(project, zoom_app, user_id, account_id)
    _require_retained_database_keys(zoom_app, ring)
    candidate_by_digest = {digest: kid for kid, digest in candidates}
    if len(candidate_by_digest) != len(candidates):
        raise GrantCaptureUnavailable("audit_key_conflict")
    queryset = ZoomOAuthAuthorizationLineage.objects
    if for_update:
        queryset = queryset.select_for_update()
    matches = list(
        queryset.filter(
            project=project,
            zoom_oauth_app=zoom_app,
            identity_digest__in=candidate_by_digest,
            identity_audit_key_id__isnull=False,
        )
    )
    if len(matches) > 1:
        raise GrantCaptureUnavailable("audit_key_conflict")
    if not matches:
        return None, candidates
    lineage = matches[0]
    expected_kid = candidate_by_digest[lineage.identity_digest]
    if (
        lineage.identity_audit_key_id != expected_kid
        or lineage.identity_audit_key_fingerprint != ring.key_fingerprints[expected_kid]
    ):
        raise GrantCaptureUnavailable("audit_key_conflict")
    return lineage, candidates


def close_authorization_grant_for_replacement(
    connection: ZoomOAuthConnection,
) -> GrantReplacementBoundary:
    """Close the live immutable grant before changing connection identity/generation."""

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("grant replacement requires the OAuth transaction")
    clock = configured_clock_evidence()
    boundary = database_clock_now()
    open_grants = list(
        ZoomOAuthAuthorizationGrant.objects.select_for_update().filter(
            live_connection=connection,
            generation_ended_at__isnull=True,
        )
    )
    if len(open_grants) > 1:
        raise GrantCaptureUnavailable("grant_lineage_ambiguous")
    for previous in open_grants:
        if previous.generation_started_at >= boundary:
            raise GrantCaptureUnavailable("grant_boundary_invalid")
        previous.generation_ended_at = boundary
        previous.end_clock_health_id = clock.health_id
        previous.end_clock_error_ms = clock.error_ms
        previous.end_clock_continuous = clock.continuous
        previous.live_connection = None
        previous.save(
            update_fields=[
                "generation_ended_at",
                "end_clock_health_id",
                "end_clock_error_ms",
                "end_clock_continuous",
                "live_connection",
                "updated_at",
            ]
        )
    return GrantReplacementBoundary(at=boundary, clock=clock)


def capture_authorization_grant(
    connection: ZoomOAuthConnection,
    *,
    replacement_boundary: GrantReplacementBoundary | None = None,
) -> ZoomOAuthAuthorizationGrant:
    """Open the next grant interval while the OAuth install transaction is held."""

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("grant capture requires the OAuth transaction")
    if not settings.ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE:
        raise GrantCaptureUnavailable("grant_capture_disabled")
    zoom_app = ZoomOAuthApp.objects.select_for_update().get(pk=connection.zoom_oauth_app_id)
    project = zoom_app.project
    # Lazy import avoids making the readiness module part of Django model
    # import/startup. Runtime capture is nevertheless DB-backed and fail-closed.
    from bots.zoom_deauthorization_readiness import DeauthorizationReadinessError, assert_capture_ready

    try:
        assert_capture_ready(zoom_app, in_flight_connection=connection)
    except DeauthorizationReadinessError as error:
        raise GrantCaptureUnavailable(error.code) from None
    try:
        ring = configured_audit_keyring(project, zoom_app)
    except AuditKeyringError as error:
        raise GrantCaptureUnavailable(error.code) from None
    lineage, candidates = find_provider_identity_lineage(
        project,
        zoom_app,
        connection.user_id,
        connection.account_id,
        for_update=True,
    )
    current_identity_digest = dict(candidates)[ring.current_kid]
    if replacement_boundary is None:
        boundary = database_clock_now()
        clock = configured_clock_evidence()
    else:
        boundary = replacement_boundary.at
        clock = replacement_boundary.clock

    _connection_ring, connection_candidates = connection_binding_candidates(connection)
    connection_candidate_by_digest = {
        digest: kid for kid, digest in connection_candidates
    }
    if len(connection_candidate_by_digest) != len(connection_candidates):
        raise GrantCaptureUnavailable("audit_key_conflict")
    prior_connection_grants = list(
        ZoomOAuthAuthorizationGrant.objects.select_for_update().filter(
            project=project,
            zoom_oauth_app=zoom_app,
            connection_digest__in=connection_candidate_by_digest,
        )
    )
    for prior in prior_connection_grants:
        expected_kid = connection_candidate_by_digest[prior.connection_digest]
        if (
            prior.connection_audit_key_id != expected_kid
            or prior.connection_audit_key_fingerprint
            != ring.key_fingerprints[expected_kid]
        ):
            raise GrantCaptureUnavailable("audit_key_conflict")

    connection_open_grants = list(
        ZoomOAuthAuthorizationGrant.objects.select_for_update().filter(
            live_connection=connection,
            generation_ended_at__isnull=True,
        )
    )
    if len(connection_open_grants) > 1:
        raise GrantCaptureUnavailable("grant_lineage_ambiguous")
    prior_identity_changed = bool(
        prior_connection_grants
        and (
            lineage is None
            or any(
                previous.lineage_id != lineage.pk
                for previous in prior_connection_grants
            )
        )
    )

    created = False
    if lineage is None:
        represented_prior_sequence = max(
            (grant.grant_sequence for grant in connection_open_grants),
            default=0,
        )
        incomplete_history = prior_identity_changed or zoom_app.legacy_history_unknown
        try:
            lineage = ZoomOAuthAuthorizationLineage.objects.create(
                project=project,
                zoom_oauth_app=zoom_app,
                identity_digest=current_identity_digest,
                identity_audit_key_id=ring.current_kid,
                identity_audit_key_fingerprint=ring.key_fingerprints[ring.current_kid],
                latest_grant_sequence=represented_prior_sequence,
                has_prior_grant=incomplete_history,
                history_complete=not incomplete_history,
            )
            created = True
        except IntegrityError:
            lineage, _candidates = find_provider_identity_lineage(
                project,
                zoom_app,
                connection.user_id,
                connection.account_id,
                for_update=True,
            )
            if lineage is None:
                raise GrantCaptureUnavailable("audit_key_conflict") from None

    open_grants = list(
        ZoomOAuthAuthorizationGrant.objects.select_for_update().filter(
            lineage=lineage,
            generation_ended_at__isnull=True,
        )
    )
    if len(open_grants) > 1:
        raise GrantCaptureUnavailable("grant_lineage_ambiguous")
    if created and open_grants:
        raise GrantCaptureUnavailable("grant_lineage_invalid")

    prior_grants = {grant.pk: grant for grant in [*connection_open_grants, *open_grants]}
    for previous in prior_grants.values():
        if previous.generation_started_at >= boundary:
            raise GrantCaptureUnavailable("grant_boundary_invalid")
        previous.generation_ended_at = boundary
        previous.end_clock_health_id = clock.health_id
        previous.end_clock_error_ms = clock.error_ms
        previous.end_clock_continuous = clock.continuous
        previous.live_connection = None
        previous.save(
            update_fields=[
                "generation_ended_at",
                "end_clock_health_id",
                "end_clock_error_ms",
                "end_clock_continuous",
                "live_connection",
                "updated_at",
            ]
        )

    next_sequence = lineage.latest_grant_sequence + 1
    if next_sequence > 1:
        lineage.has_prior_grant = True
    lineage.latest_grant_sequence = next_sequence
    lineage.save(update_fields=["latest_grant_sequence", "has_prior_grant", "updated_at"])

    return ZoomOAuthAuthorizationGrant.objects.create(
        project=project,
        zoom_oauth_app=zoom_app,
        lineage=lineage,
        grant_sequence=next_sequence,
        live_connection=connection,
        connection_digest=connection_binding_digest(connection),
        connection_audit_key_id=ring.current_kid,
        connection_audit_key_fingerprint=ring.key_fingerprints[ring.current_kid],
        identity_digest=lineage.identity_digest,
        identity_audit_key_id=lineage.identity_audit_key_id,
        identity_audit_key_fingerprint=lineage.identity_audit_key_fingerprint,
        authorization_generation=connection.authorization_generation,
        generation_started_at=boundary,
        start_clock_health_id=clock.health_id,
        start_clock_error_ms=clock.error_ms,
        start_clock_continuous=clock.continuous,
        legacy_history=not lineage.history_complete,
    )
