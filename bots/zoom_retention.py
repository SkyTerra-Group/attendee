"""Fail-closed Zoom connection revocation and project-scoped bot purging.

This module deliberately emits no provider response bodies, target identifiers,
or exception strings.  Its public results are limited to opaque operation IDs,
keyed target digests, stable states, and bounded internal failure codes.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from datetime import timedelta

import requests
from django.conf import settings
from django.core.files.storage import storages
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from bots.bot_runtime_fence import confirm_bot_runtime_absence
from bots.models import (
    AsyncTranscription,
    AudioChunk,
    Bot,
    BotChatMessageRequest,
    BotDebugScreenshot,
    BotEvent,
    BotLogEntry,
    BotMediaRequest,
    BotResourceSnapshot,
    BotStates,
    ChatMessage,
    CreditTransaction,
    MediaBlob,
    Participant,
    ParticipantEvent,
    Project,
    Recording,
    Utterance,
    WebhookDeliveryAttempt,
    WebhookSubscription,
    ZoomOAuthConnection,
    ZoomOAuthConnectionStates,
    ZoomRemovalOperation,
    ZoomRemovalOperationPhases,
    ZoomRemovalOperationSources,
    ZoomRemovalOperationStates,
    ZoomRemovalOperationTypes,
)

ZOOM_TOKEN_URL = "https://zoom.us/oauth/token"
ZOOM_REVOKE_URL = "https://zoom.us/oauth/revoke"
PROVIDER_TIMEOUT_SECONDS = 30
LEASE_SECONDS = 300
RECEIPT_RETENTION_DAYS = 30
MAX_PURGE_TARGETS = 100
PENDING_REVOKE_ACCESS_TOKEN_KEY = "_zoom_retention_pending_revoke_access_token"

_COMPLETED_STATES = {
    ZoomRemovalOperationStates.REVOKED,
    ZoomRemovalOperationStates.PURGED,
}


class CrossProjectTarget(Exception):
    pass


class OperationConflict(Exception):
    def __init__(self, canonical_operation_id=None):
        self.canonical_operation_id = canonical_operation_id


class StorageVerificationError(Exception):
    pass


class DatabaseVerificationError(Exception):
    pass


class LeaseLost(Exception):
    pass


class UntrustedDeauthorizationSource(Exception):
    pass


@dataclass(frozen=True)
class ProviderOutcome:
    terminal: bool
    failure_code: str | None = None


def target_digest(project: Project, operation_type: str, target_object_id: str) -> str:
    """Return a domain-separated keyed digest without retaining the raw target."""

    configured_key = settings.CREDENTIALS_ENCRYPTION_KEY
    if isinstance(configured_key, str):
        configured_key = configured_key.encode("utf-8")
    digest_key = hmac.new(configured_key, b"attendee-zoom-removal-digest-v1", hashlib.sha256).digest()
    material = f"{project.pk}:{operation_type}:{target_object_id}".encode("utf-8")
    return hmac.new(digest_key, material, hashlib.sha256).hexdigest()


def operation_result(operation: ZoomRemovalOperation) -> dict:
    result = {
        "operation_id": str(operation.operation_id),
        "operation_type": operation.operation_type,
        "target_digest": operation.target_digest,
        "state": operation.state,
        "phase": operation.phase,
    }
    if operation.failure_code:
        result["failure_code"] = operation.failure_code
    if operation.completed_at:
        result["completed_at"] = operation.completed_at.isoformat()
    return result


def get_project_operation(project: Project, operation_id: uuid.UUID) -> ZoomRemovalOperation | None:
    return ZoomRemovalOperation.objects.filter(project=project, operation_id=operation_id).first()


def delete_expired_receipts() -> int:
    deleted, _ = ZoomRemovalOperation.objects.filter(state__in=_COMPLETED_STATES, expires_at__lte=timezone.now()).delete()
    return deleted


def _target_exists_in_other_project(model, project: Project, object_id: str, project_path: str) -> bool:
    return model.objects.filter(object_id=object_id).exclude(**{project_path: project}).exists()


def _get_or_create_operation(
    *,
    project: Project,
    operation_id: uuid.UUID,
    operation_type: str,
    target_object_id: str,
    source: str | None = None,
    target_generation: uuid.UUID | None = None,
) -> ZoomRemovalOperation:
    digest = target_digest(project, operation_type, target_object_id)

    existing = ZoomRemovalOperation.objects.filter(project=project, operation_id=operation_id).first()
    if existing:
        if existing.operation_type != operation_type or existing.target_digest != digest:
            raise OperationConflict()
        if target_generation and existing.target_generation and existing.target_generation != target_generation:
            raise OperationConflict()
        return existing

    existing_target = ZoomRemovalOperation.objects.filter(project=project, operation_type=operation_type, target_digest=digest).first()
    if existing_target:
        raise OperationConflict(existing_target.operation_id)

    try:
        with transaction.atomic():
            return ZoomRemovalOperation.objects.create(
                project=project,
                operation_id=operation_id,
                operation_type=operation_type,
                source=source,
                target_digest=digest,
                target_object_id=target_object_id,
                target_generation=target_generation,
            )
    except IntegrityError:
        existing = ZoomRemovalOperation.objects.filter(project=project, operation_id=operation_id).first()
        if existing and existing.operation_type == operation_type and existing.target_digest == digest:
            return existing
        existing_target = ZoomRemovalOperation.objects.filter(project=project, operation_type=operation_type, target_digest=digest).first()
        raise OperationConflict(existing_target.operation_id if existing_target else None)


def _claim_operation(operation: ZoomRemovalOperation) -> tuple[ZoomRemovalOperation, uuid.UUID | None]:
    now = timezone.now()
    with transaction.atomic():
        current = ZoomRemovalOperation.objects.select_for_update().get(pk=operation.pk)
        if current.state in _COMPLETED_STATES:
            return current, None
        if current.lease_token and current.lease_expires_at and current.lease_expires_at > now:
            return current, None

        lease_token = uuid.uuid4()
        current.lease_token = lease_token
        current.lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
        current.attempt_count = F("attempt_count") + 1
        current.save(update_fields=["lease_token", "lease_expires_at", "attempt_count", "updated_at"])
        current.refresh_from_db(fields=["attempt_count"])
        return current, lease_token


def _update_claimed(operation_id: int, lease_token: uuid.UUID, **values) -> ZoomRemovalOperation:
    with transaction.atomic():
        operation = ZoomRemovalOperation.objects.select_for_update().get(pk=operation_id)
        if operation.lease_token != lease_token:
            raise LeaseLost()
        for field, value in values.items():
            setattr(operation, field, value)
        operation.lease_expires_at = timezone.now() + timedelta(seconds=LEASE_SECONDS)
        update_fields = [*values.keys(), "lease_expires_at", "updated_at"]
        operation.save(update_fields=update_fields)
        return operation


def _release_claim(operation_id: int, lease_token: uuid.UUID, *, state: str | None = None, failure_code: str | None = None) -> ZoomRemovalOperation:
    with transaction.atomic():
        operation = ZoomRemovalOperation.objects.select_for_update().get(pk=operation_id)
        if operation.lease_token != lease_token:
            return operation
        if state is not None:
            operation.state = state
        operation.failure_code = failure_code
        operation.lease_token = None
        operation.lease_expires_at = None
        operation.save(update_fields=["state", "failure_code", "lease_token", "lease_expires_at", "updated_at"])
        return operation


def _complete_claim(operation_id: int, lease_token: uuid.UUID, state: str) -> ZoomRemovalOperation:
    now = timezone.now()
    with transaction.atomic():
        operation = ZoomRemovalOperation.objects.select_for_update().get(pk=operation_id)
        if operation.lease_token != lease_token:
            raise LeaseLost()
        operation.state = state
        operation.phase = ZoomRemovalOperationPhases.COMPLETE
        operation.failure_code = None
        operation.target_object_id = None
        operation.storage_manifest = {}
        operation.lease_token = None
        operation.lease_expires_at = None
        operation.completed_at = now
        operation.expires_at = now + timedelta(days=RECEIPT_RETENTION_DAYS)
        operation.save(
            update_fields=[
                "state",
                "phase",
                "failure_code",
                "target_object_id",
                "storage_manifest",
                "lease_token",
                "lease_expires_at",
                "completed_at",
                "expires_at",
                "updated_at",
            ]
        )
        return operation


def _safe_json(response):
    try:
        payload = response.json()
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _is_documented_terminal_revoke_response(status_code: int, payload: dict | None) -> bool:
    """Recognize only Zoom's stable revoke-endpoint code/schema allowlist."""

    return status_code == 400 and isinstance(payload, dict) and type(payload.get("code")) is int and payload.get("code") == 4741 and isinstance(payload.get("message"), str)


def _refresh_access_token_for_revoke(connection: ZoomOAuthConnection) -> tuple[str | None, ProviderOutcome | None]:
    try:
        credentials = connection.get_credentials() or {}
        if not isinstance(credentials, dict):
            return None, ProviderOutcome(False, "credentials_unavailable")
        pending_access_token = credentials.get(PENDING_REVOKE_ACCESS_TOKEN_KEY)
        if isinstance(pending_access_token, str) and pending_access_token:
            return pending_access_token, None
        refresh_token = credentials.get("refresh_token")
        client_id = connection.zoom_oauth_app.client_id
        client_secret = connection.zoom_oauth_app.client_secret
    except Exception:
        return None, ProviderOutcome(False, "credentials_unavailable")

    if not refresh_token or not client_id or not client_secret:
        return None, ProviderOutcome(False, "credentials_unavailable")

    try:
        response = requests.post(
            ZOOM_TOKEN_URL,
            auth=(client_id, client_secret),
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            timeout=PROVIDER_TIMEOUT_SECONDS,
        )
    except requests.RequestException:
        return None, ProviderOutcome(False, "refresh_transport_unknown")

    if response.status_code == 429:
        return None, ProviderOutcome(False, "refresh_rate_limited")
    if response.status_code >= 500:
        return None, ProviderOutcome(False, "refresh_provider_unavailable")
    payload = _safe_json(response)
    if payload is None:
        return None, ProviderOutcome(False, "refresh_malformed_response")
    if response.status_code != 200:
        return None, ProviderOutcome(False, "refresh_unrecognized_response")

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return None, ProviderOutcome(False, "refresh_missing_access_token")

    credentials[PENDING_REVOKE_ACCESS_TOKEN_KEY] = access_token
    rotated_refresh = payload.get("refresh_token")
    if isinstance(rotated_refresh, str) and rotated_refresh:
        credentials["refresh_token"] = rotated_refresh
    try:
        # Persist the exact revoke credential before the provider call. A lost
        # response can then replay the identical request without guessing from
        # a later generic refresh failure.
        connection.set_credentials(credentials)
    except Exception:
        return None, ProviderOutcome(False, "refresh_persist_failed")

    return access_token, None


def _revoke_at_zoom(connection: ZoomOAuthConnection) -> ProviderOutcome:
    access_token, refresh_outcome = _refresh_access_token_for_revoke(connection)
    if refresh_outcome:
        return refresh_outcome

    try:
        response = requests.post(
            ZOOM_REVOKE_URL,
            auth=(connection.zoom_oauth_app.client_id, connection.zoom_oauth_app.client_secret),
            data={"token": access_token},
            timeout=PROVIDER_TIMEOUT_SECONDS,
        )
    except requests.RequestException:
        return ProviderOutcome(False, "revoke_transport_unknown")

    if response.status_code == 429:
        return ProviderOutcome(False, "revoke_rate_limited")
    if response.status_code >= 500:
        return ProviderOutcome(False, "revoke_provider_unavailable")
    payload = _safe_json(response)
    if payload is None:
        return ProviderOutcome(False, "revoke_malformed_response")
    if response.status_code == 200 and payload.get("status") == "success":
        return ProviderOutcome(True)
    if _is_documented_terminal_revoke_response(response.status_code, payload):
        return ProviderOutcome(True, "already_revoked_or_expired")
    return ProviderOutcome(False, "revoke_unrecognized_response")


def process_connection_revoke(
    *,
    project: Project,
    operation_id: uuid.UUID,
    connection_object_id: str,
    source: str,
) -> ZoomRemovalOperation:
    if source != ZoomRemovalOperationSources.SKYTERRA_INITIATED:
        # A normal project API credential cannot attest a signed Zoom event.
        # A purpose-bound cross-service trust protocol is intentionally not
        # invented in this default-off S1 change.
        raise UntrustedDeauthorizationSource()
    if _target_exists_in_other_project(ZoomOAuthConnection, project, connection_object_id, "zoom_oauth_app__project"):
        raise CrossProjectTarget()

    initial_connection = ZoomOAuthConnection.objects.filter(
        object_id=connection_object_id,
        zoom_oauth_app__project=project,
    ).first()

    operation = _get_or_create_operation(
        project=project,
        operation_id=operation_id,
        operation_type=ZoomRemovalOperationTypes.REVOKE_CONNECTION,
        target_object_id=connection_object_id,
        source=source,
        target_generation=initial_connection.authorization_generation if initial_connection else None,
    )
    operation, lease_token = _claim_operation(operation)
    if lease_token is None:
        return operation

    connection = ZoomOAuthConnection.objects.filter(object_id=connection_object_id, zoom_oauth_app__project=project).select_related("zoom_oauth_app").first()
    if connection is None:
        return _release_claim(operation.pk, lease_token, state=ZoomRemovalOperationStates.NOT_FOUND_UNPROVED, failure_code="connection_absence_unproved")

    try:
        with transaction.atomic():
            claimed = ZoomRemovalOperation.objects.select_for_update().get(pk=operation.pk)
            if claimed.lease_token != lease_token:
                raise LeaseLost()
            locked_connection = ZoomOAuthConnection.objects.select_for_update().select_related("zoom_oauth_app").filter(pk=connection.pk, zoom_oauth_app__project=project).first()
            if locked_connection is None:
                raise DatabaseVerificationError()
            if claimed.target_generation and claimed.target_generation != locked_connection.authorization_generation:
                raise DatabaseVerificationError()
            if claimed.target_generation is None:
                claimed.target_generation = locked_connection.authorization_generation
                claimed.save(update_fields=["target_generation", "updated_at"])
            if locked_connection.state != ZoomOAuthConnectionStates.REMOVING:
                locked_connection.state = ZoomOAuthConnectionStates.REMOVING
                locked_connection.save(update_fields=["state", "updated_at"])
            connection = locked_connection

        provider_outcome = _revoke_at_zoom(connection)

        if not provider_outcome.terminal:
            return _release_claim(
                operation.pk,
                lease_token,
                state=ZoomRemovalOperationStates.REVOKE_UNKNOWN,
                failure_code=provider_outcome.failure_code,
            )

        now = timezone.now()
        with transaction.atomic():
            claimed = ZoomRemovalOperation.objects.select_for_update().get(pk=operation.pk)
            if claimed.lease_token != lease_token:
                raise LeaseLost()
            locked_connection = (
                ZoomOAuthConnection.objects.select_for_update()
                .filter(
                    pk=connection.pk,
                    zoom_oauth_app__project=project,
                    authorization_generation=claimed.target_generation,
                    state=ZoomOAuthConnectionStates.REMOVING,
                )
                .first()
            )
            if locked_connection is None:
                raise DatabaseVerificationError()
            WebhookDeliveryAttempt.objects.filter(zoom_oauth_connection=locked_connection).delete()
            locked_connection.delete()
            if ZoomOAuthConnection.objects.filter(pk=connection.pk).exists():
                raise DatabaseVerificationError()

            claimed.state = ZoomRemovalOperationStates.REVOKED
            claimed.phase = ZoomRemovalOperationPhases.COMPLETE
            claimed.failure_code = provider_outcome.failure_code
            claimed.target_object_id = None
            claimed.storage_manifest = {}
            claimed.lease_token = None
            claimed.lease_expires_at = None
            claimed.completed_at = now
            claimed.expires_at = now + timedelta(days=RECEIPT_RETENTION_DAYS)
            claimed.save()
            return claimed
    except LeaseLost:
        return ZoomRemovalOperation.objects.get(pk=operation.pk)
    except Exception:
        return _release_claim(operation.pk, lease_token, state=ZoomRemovalOperationStates.REVOKE_UNKNOWN, failure_code="local_revoke_finalize_failed")


def _storage_manifest(bot: Bot) -> dict:
    recordings = list(bot.recordings.all())
    return {
        "recordings": sorted({recording.file.name for recording in recordings if recording.file and recording.file.name}),
        "screenshots": sorted({screenshot.file.name for screenshot in BotDebugScreenshot.objects.filter(bot_event__bot=bot) if screenshot.file and screenshot.file.name}),
        "audio": sorted({chunk.audio_blob_remote_file.name for chunk in AudioChunk.objects.filter(recording__bot=bot) if chunk.audio_blob_remote_file and chunk.audio_blob_remote_file.name}),
        "audio_prefixes": sorted({f"audio-blobs/{bot.object_id}-{recording.object_id}" for recording in recordings}),
    }


def _list_storage_tree(storage, prefix: str) -> list[str]:
    try:
        directories, files = storage.listdir(prefix)
    except FileNotFoundError:
        return []
    found = [f"{prefix.rstrip('/')}/{name}" for name in files]
    for directory in directories:
        found.extend(_list_storage_tree(storage, f"{prefix.rstrip('/')}/{directory}"))
    return found


def _delete_and_verify_storage(manifest: dict) -> None:
    exact_groups = (
        (storages["recordings"], manifest.get("recordings", [])),
        (storages["bot_debug_screenshots"], manifest.get("screenshots", [])),
        (storages["audio_chunks"], manifest.get("audio", [])),
    )
    for storage, names in exact_groups:
        for name in names:
            storage.delete(name)

    audio_storage = storages["audio_chunks"]
    for prefix in manifest.get("audio_prefixes", []):
        for name in _list_storage_tree(audio_storage, prefix):
            audio_storage.delete(name)

    for storage, names in exact_groups:
        if any(storage.exists(name) for name in names):
            raise StorageVerificationError()
    if any(_list_storage_tree(audio_storage, prefix) for prefix in manifest.get("audio_prefixes", [])):
        raise StorageVerificationError()


def _delete_bot_dependents_and_row(
    bot: Bot,
    digest: str,
    operation_id: int,
    lease_token: uuid.UUID,
) -> ZoomRemovalOperation:
    bot_pk = bot.pk
    media_blob_ids = list(BotMediaRequest.objects.filter(bot_id=bot_pk, media_blob__isnull=False).values_list("media_blob_id", flat=True))

    with transaction.atomic():
        operation = ZoomRemovalOperation.objects.select_for_update().get(pk=operation_id)
        if operation.lease_token != lease_token:
            raise LeaseLost()
        locked_bot = Bot.objects.select_for_update().get(pk=bot_pk)
        if locked_bot.removal_requested_at is None or locked_bot.runtime_absence_confirmed_at is None or locked_bot.runtime_absence_generation != locked_bot.runtime_generation or operation.target_generation != locked_bot.runtime_generation:
            raise DatabaseVerificationError()
        WebhookDeliveryAttempt.objects.filter(bot_id=bot_pk).delete()
        WebhookSubscription.objects.filter(bot_id=bot_pk).delete()
        BotChatMessageRequest.objects.filter(bot_id=bot_pk).delete()
        BotMediaRequest.objects.filter(bot_id=bot_pk).delete()
        ChatMessage.objects.filter(bot_id=bot_pk).delete()
        Utterance.objects.filter(recording__bot_id=bot_pk).delete()
        AudioChunk.objects.filter(recording__bot_id=bot_pk).delete()
        AsyncTranscription.objects.filter(recording__bot_id=bot_pk).delete()
        Recording.objects.filter(bot_id=bot_pk).delete()
        ParticipantEvent.objects.filter(participant__bot_id=bot_pk).delete()
        Participant.objects.filter(bot_id=bot_pk).delete()
        BotDebugScreenshot.objects.filter(bot_event__bot_id=bot_pk).delete()
        BotEvent.objects.filter(bot_id=bot_pk).delete()
        BotLogEntry.objects.filter(bot_id=bot_pk).delete()
        BotResourceSnapshot.objects.filter(bot_id=bot_pk).delete()
        CreditTransaction.objects.filter(bot_id=bot_pk).update(bot=None, description=f"For purged bot {digest}")
        MediaBlob.objects.filter(pk__in=media_blob_ids, bot_media_requests__isnull=True).delete()

        if WebhookDeliveryAttempt.objects.filter(bot_id=bot_pk).exists() or CreditTransaction.objects.filter(bot_id=bot_pk).exists():
            raise DatabaseVerificationError()

        # This is intentionally the final target-owned row deletion.
        locked_bot.delete()
        if Bot.objects.filter(pk=bot_pk).exists():
            raise DatabaseVerificationError()

        # The database-deleted proof phase commits atomically with the target's
        # last row. A process crash can therefore never turn our own deletion
        # into an unproved bare 404 on replay.
        operation.phase = ZoomRemovalOperationPhases.DATABASE_DELETED
        operation.state = ZoomRemovalOperationStates.DATA_DELETED
        operation.failure_code = None
        operation.lease_expires_at = timezone.now() + timedelta(seconds=LEASE_SECONDS)
        operation.save(update_fields=["phase", "state", "failure_code", "lease_expires_at", "updated_at"])
        return operation


def _database_absence_is_verified(project: Project, target_object_id: str) -> bool:
    return not Bot.objects.filter(project=project, object_id=target_object_id).exists()


def _fence_bot_for_removal(bot: Bot, operation_id: int, lease_token: uuid.UUID) -> Bot:
    with transaction.atomic():
        operation = ZoomRemovalOperation.objects.select_for_update().get(pk=operation_id)
        if operation.lease_token != lease_token:
            raise LeaseLost()
        locked_bot = Bot.objects.select_for_update().get(pk=bot.pk)
        if operation.target_generation and operation.target_generation != locked_bot.runtime_generation:
            raise DatabaseVerificationError()
        if operation.target_generation is None:
            operation.target_generation = locked_bot.runtime_generation
            operation.save(update_fields=["target_generation", "updated_at"])
        if locked_bot.removal_requested_at is None:
            locked_bot.removal_requested_at = timezone.now()
            locked_bot.save(update_fields=["removal_requested_at", "updated_at"])
        return locked_bot


def _bot_is_purgeable_state(bot: Bot) -> bool:
    if bot.state in BotStates.post_meeting_states():
        return True
    return bot.state in {BotStates.SCHEDULED, BotStates.STAGED} and bot.runtime_launch_started_at is None


def process_bot_purge(*, project: Project, operation_id: uuid.UUID, bot_object_id: str) -> ZoomRemovalOperation:
    if _target_exists_in_other_project(Bot, project, bot_object_id, "project"):
        raise CrossProjectTarget()

    operation = _get_or_create_operation(
        project=project,
        operation_id=operation_id,
        operation_type=ZoomRemovalOperationTypes.PURGE_BOT,
        target_object_id=bot_object_id,
    )
    operation, lease_token = _claim_operation(operation)
    if lease_token is None:
        return operation

    try:
        operation.refresh_from_db()
        if operation.phase != ZoomRemovalOperationPhases.DATABASE_DELETED:
            bot = Bot.objects.filter(project=project, object_id=bot_object_id).first()
            if bot is None:
                return _release_claim(operation.pk, lease_token, state=ZoomRemovalOperationStates.NOT_FOUND_UNPROVED, failure_code="bot_absence_unproved")
            bot = _fence_bot_for_removal(bot, operation.pk, lease_token)
            if not _bot_is_purgeable_state(bot):
                return _release_claim(operation.pk, lease_token, state=ZoomRemovalOperationStates.PENDING_ACTIVE, failure_code="bot_active")
            if bot.runtime_absence_generation != bot.runtime_generation or bot.runtime_absence_confirmed_at is None:
                bot = confirm_bot_runtime_absence(bot.pk)
                if bot is None:
                    return _release_claim(
                        operation.pk,
                        lease_token,
                        state=ZoomRemovalOperationStates.PENDING_ACTIVE,
                        failure_code="runtime_absence_unproved",
                    )

        if operation.phase == ZoomRemovalOperationPhases.PENDING:
            manifest = operation.storage_manifest or _storage_manifest(bot)
            if not operation.storage_manifest:
                operation = _update_claimed(operation.pk, lease_token, storage_manifest=manifest)
            _delete_and_verify_storage(manifest)
            operation = _update_claimed(
                operation.pk,
                lease_token,
                phase=ZoomRemovalOperationPhases.STORAGE_VERIFIED,
                state=ZoomRemovalOperationStates.PENDING,
                failure_code=None,
            )

        if operation.phase == ZoomRemovalOperationPhases.STORAGE_VERIFIED:
            bot = Bot.objects.get(project=project, object_id=bot_object_id)
            if bot.state in {BotStates.DATA_DELETED, BotStates.SCHEDULED, BotStates.STAGED}:
                bot.ensure_data_deleted()
            else:
                bot.delete_data()
            operation = _update_claimed(
                operation.pk,
                lease_token,
                phase=ZoomRemovalOperationPhases.DATA_DELETED,
                state=ZoomRemovalOperationStates.DATA_DELETED,
                failure_code=None,
            )

        if operation.phase == ZoomRemovalOperationPhases.DATA_DELETED:
            bot = Bot.objects.get(project=project, object_id=bot_object_id)
            operation = _delete_bot_dependents_and_row(bot, operation.target_digest, operation.pk, lease_token)

        if operation.phase == ZoomRemovalOperationPhases.DATABASE_DELETED:
            _delete_and_verify_storage(operation.storage_manifest)
            if not _database_absence_is_verified(project, bot_object_id):
                raise DatabaseVerificationError()
            return _complete_claim(operation.pk, lease_token, ZoomRemovalOperationStates.PURGED)

        raise DatabaseVerificationError()
    except LeaseLost:
        return ZoomRemovalOperation.objects.get(pk=operation.pk)
    except Exception:
        # Do not include the exception or its string representation in logs,
        # storage, or responses. Preserve a durable ``data_deleted`` phase.
        current = ZoomRemovalOperation.objects.get(pk=operation.pk)
        failure_state = ZoomRemovalOperationStates.DATA_DELETED if current.phase in {ZoomRemovalOperationPhases.DATA_DELETED, ZoomRemovalOperationPhases.DATABASE_DELETED} else ZoomRemovalOperationStates.PURGE_UNKNOWN
        return _release_claim(operation.pk, lease_token, state=failure_state, failure_code="purge_step_failed")
