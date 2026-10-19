"""Immutable Zoom authorization lineage capture for signed deauthorization."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db import connection as database_connection

from bots.models import (
    Project,
    ZoomOAuthApp,
    ZoomOAuthAuthorizationGrant,
    ZoomOAuthAuthorizationLineage,
    ZoomOAuthConnection,
)


class GrantCaptureUnavailable(Exception):
    pass


@dataclass(frozen=True)
class ClockEvidence:
    health_id: str
    error_ms: int
    continuous: bool


_CLOCK_HEALTH_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")


def database_clock_now():
    with database_connection.cursor() as cursor:
        cursor.execute("SELECT clock_timestamp()")
        return cursor.fetchone()[0]


def configured_clock_evidence() -> ClockEvidence:
    health_id = settings.ZOOM_DEAUTH_DB_CLOCK_HEALTH_ID
    error_ms = settings.ZOOM_DEAUTH_DB_CLOCK_ERROR_MS
    continuous = settings.ZOOM_DEAUTH_DB_CLOCK_CONTINUOUS
    if (
        type(health_id) is not str
        or not health_id
        or len(health_id.encode("utf-8")) > 64
        or not _CLOCK_HEALTH_ID_RE.fullmatch(health_id)
        or type(error_ms) is not int
        or error_ms < 0
        or error_ms > 1000
        or continuous is not True
    ):
        raise GrantCaptureUnavailable("clock_evidence_invalid")
    return ClockEvidence(health_id=health_id, error_ms=error_ms, continuous=continuous)


def _audit_key() -> bytes:
    configured = settings.ZOOM_REMOVAL_AUDIT_KEY
    if type(configured) is not str or len(configured.encode("utf-8")) < 32:
        raise GrantCaptureUnavailable("audit_key_unconfigured")
    return configured.encode("utf-8")


def _keyed_digest(domain: str, *parts: str) -> str:
    key = hmac.new(_audit_key(), b"attendee-zoom-removal-audit-v1", hashlib.sha256).digest()
    material = "\x00".join((domain, *parts)).encode("utf-8")
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def provider_identity_digest(project: Project, zoom_app: ZoomOAuthApp, user_id: str, account_id: str) -> str:
    return _keyed_digest(
        "zoom-provider-identity-v1",
        project.object_id,
        str(zoom_app.deauthorization_binding_id),
        user_id,
        account_id,
    )


def connection_binding_digest(connection: ZoomOAuthConnection) -> str:
    return _keyed_digest(
        "zoom-connection-v1",
        connection.zoom_oauth_app.project.object_id,
        str(connection.zoom_oauth_app.deauthorization_binding_id),
        connection.object_id,
    )


def expected_client_id_digest(client_id: str) -> str:
    return hashlib.sha256(client_id.encode("utf-8")).hexdigest()


def grant_binding_digest(binding_id) -> str:
    return hashlib.sha256(str(binding_id).encode("ascii")).hexdigest()


def capture_authorization_grant(connection: ZoomOAuthConnection) -> ZoomOAuthAuthorizationGrant:
    """Open the next grant interval while the OAuth install transaction is held."""

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("grant capture requires the OAuth transaction")
    zoom_app = ZoomOAuthApp.objects.select_for_update().get(pk=connection.zoom_oauth_app_id)
    project = zoom_app.project
    identity_digest = provider_identity_digest(project, zoom_app, connection.user_id, connection.account_id)
    boundary = database_clock_now()
    clock = configured_clock_evidence()

    connection_open_grants = list(
        ZoomOAuthAuthorizationGrant.objects.select_for_update().filter(
            live_connection=connection,
            generation_ended_at__isnull=True,
        )
    )
    if len(connection_open_grants) > 1:
        raise GrantCaptureUnavailable("grant_lineage_ambiguous")
    prior_identity_changed = bool(connection_open_grants and connection_open_grants[0].identity_digest != identity_digest)

    try:
        lineage, created = ZoomOAuthAuthorizationLineage.objects.select_for_update().get_or_create(
            project=project,
            zoom_oauth_app=zoom_app,
            identity_digest=identity_digest,
            defaults={
                "latest_grant_sequence": 0,
                "has_prior_grant": prior_identity_changed,
                "history_complete": not prior_identity_changed,
            },
        )
    except IntegrityError:
        lineage = ZoomOAuthAuthorizationLineage.objects.select_for_update().get(
            project=project,
            zoom_oauth_app=zoom_app,
            identity_digest=identity_digest,
        )
        created = False

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
        identity_digest=identity_digest,
        authorization_generation=connection.authorization_generation,
        generation_started_at=boundary,
        start_clock_health_id=clock.health_id,
        start_clock_error_ms=clock.error_ms,
        start_clock_continuous=clock.continuous,
        legacy_history=not lineage.history_complete,
    )
