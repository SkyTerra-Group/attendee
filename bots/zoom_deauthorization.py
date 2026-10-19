"""Grant-bound settlement of Client-Agent verified Zoom deauthorization."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as datetime_timezone

from django.db import connection as database_connection
from django.db import transaction

from bots.models import (
    Project,
    WebhookDeliveryAttempt,
    ZoomDeauthorizationAssertionReceipt,
    ZoomDeauthorizationEventBinding,
    ZoomDeauthorizationResolutionOutcomes,
    ZoomDeauthorizationTargetResolution,
    ZoomOAuthApp,
    ZoomOAuthAuthorizationGrant,
    ZoomOAuthAuthorizationLineage,
    ZoomOAuthConnection,
    ZoomOAuthConnectionStates,
    ZoomRemovalOperation,
    ZoomRemovalOperationPhases,
    ZoomRemovalOperationSources,
    ZoomRemovalOperationStates,
    ZoomRemovalOperationTypes,
)
from bots.zoom_deauthorization_assertion import (
    CREATE_IF_FRESH,
    EXISTING_ONLY,
    TEMPORAL_POLICY,
    VerifiedDeauthorizationAssertion,
)
from bots.zoom_deauthorization_grants import (
    GrantCaptureUnavailable,
    configured_clock_evidence,
    database_clock_now,
    expected_client_id_digest,
    provider_identity_digest,
)
from bots.zoom_retention import (
    RECEIPT_RETENTION_DAYS,
    OperationConflict,
    _claim_alternate_identifier,
    _get_or_create_operation,
    canonical_operation_id,
    get_project_operation,
    operation_result,
)

U_SECONDS = 62
MAX_FRESH_SPAN_SECONDS = 29
MAX_COMBINED_CLOCK_ERROR_MS = 1000

_TARGET_FREE_OUTCOMES = {
    ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_TEMPORAL_ORDER,
    ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_PROVIDER_CLOCK,
    ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND,
    ZoomDeauthorizationResolutionOutcomes.CLOCK_UNTRUSTED,
}

_EVIDENCE_SNAPSHOT_FIELDS = {
    "temporal_policy",
    "zoom_event_at",
    "zoom_request_signed_at",
    "first_verified_at",
    "binding_attempt_iat",
    "attendee_binding_received_at",
    "zoom_event_precision_ms",
    "zoom_request_precision_ms",
    "generation_started_at",
    "generation_ended_at",
    "client_clock_health_id",
    "client_clock_continuous",
    "client_clock_step_free",
    "client_clock_error_ms",
    "attendee_boundary_clock_health_ids",
    "attendee_boundary_clock_error_ms",
    "attendee_boundary_clock_continuous",
    "grant_binding_id",
    "connection_generation",
    "lineage_sequence",
    "history_complete",
    "has_prior_grant",
}


class DeauthorizationServiceError(Exception):
    def __init__(self, code: str, *, status_code: int = 409, operation_id=None, recovery=None):
        self.code = code
        self.status_code = status_code
        self.operation_id = operation_id
        self.recovery = recovery or {}
        super().__init__(code)


@dataclass(frozen=True)
class CommittedDeauthorizationError:
    """A bounded conflict whose safe canonical allocation must commit."""

    code: str
    status_code: int = 409
    operation_id: uuid.UUID | None = None
    recovery: dict | None = None


def _canonical_json(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _utc_iso(value: datetime | None):
    if value is None:
        return None
    return value.astimezone(datetime_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _datetime_from_epoch(value: int) -> datetime:
    return datetime.fromtimestamp(value, tz=datetime_timezone.utc)


def _event_lock(project_id: int, app_id: int, event_digest: str) -> None:
    if database_connection.vendor != "postgresql":
        return
    material = hashlib.sha256(f"zoom-deauth-event:{project_id}:{app_id}:{event_digest}".encode("ascii")).digest()
    signed_key = int.from_bytes(material[:8], "big", signed=True)
    with database_connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [signed_key])


def _nonce_lock(project_id: int, app_id: int, issuer_id: str, nonce_digest: str) -> None:
    if database_connection.vendor != "postgresql":
        return
    material = hashlib.sha256(
        f"zoom-deauth-nonce:{project_id}:{app_id}:{issuer_id}:{nonce_digest}".encode("utf-8")
    ).digest()
    signed_key = int.from_bytes(material[:8], "big", signed=True)
    with database_connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [signed_key])


def _exact_app(project: Project, assertion: VerifiedDeauthorizationAssertion) -> ZoomOAuthApp:
    configured_id = assertion.signer["zoom_oauth_app_id"]
    try:
        app = ZoomOAuthApp.objects.select_for_update().get(
            pk=configured_id,
            project=project,
            deauthorization_binding_id=assertion.claims["zoom_oauth_app_binding"],
        )
    except (ZoomOAuthApp.DoesNotExist, ValueError, TypeError):
        raise DeauthorizationServiceError("scope_not_found", status_code=404) from None
    configured_digest = assertion.signer["expected_client_id_digest"]
    if type(configured_digest) is not str or len(configured_digest) != 64:
        raise DeauthorizationServiceError("signer_registry_invalid", status_code=401)
    if not hmac.compare_digest(expected_client_id_digest(app.client_id), configured_digest):
        raise DeauthorizationServiceError("signer_registry_invalid", status_code=401)
    return app


def _binding_recovery(binding: ZoomDeauthorizationEventBinding) -> dict:
    return {
        "event_binding_id": str(binding.binding_id),
        "event_binding_version": binding.binding_version,
        "temporal_evidence_digest": binding.binding_evidence_digest,
    }


def _validate_existing_binding_claims(binding: ZoomDeauthorizationEventBinding, assertion: VerifiedDeauthorizationAssertion) -> None:
    claims = assertion.claims
    snapshot = binding.evidence_snapshot
    immutable = {
        "zoom_event_at": claims["zoom_event_at"],
        "zoom_request_signed_at": claims["zoom_request_signed_at"],
        "first_verified_at": claims["first_verified_at"],
        "zoom_event_precision_ms": claims["zoom_event_precision_ms"],
        "zoom_request_precision_ms": claims["zoom_request_precision_ms"],
        "client_clock_health_id": claims["client_clock_health_id"],
        "client_clock_continuous": claims["client_clock_continuous"],
        "client_clock_step_free": claims["client_clock_step_free"],
        "client_clock_error_ms": claims["client_clock_error_ms"],
    }
    if type(snapshot) is not dict or set(snapshot) != _EVIDENCE_SNAPSHOT_FIELDS:
        raise DeauthorizationServiceError("event_binding_conflict")
    if any(snapshot.get(name) != value for name, value in immutable.items()):
        raise DeauthorizationServiceError("event_binding_conflict")
    if binding.event_digest != assertion.event_digest or binding.app_digest != assertion.app_digest:
        raise DeauthorizationServiceError("event_binding_conflict")
    if (
        snapshot["temporal_policy"] != binding.temporal_policy
        or snapshot["grant_binding_id"] != str(binding.grant_binding_id)
        or snapshot["connection_generation"] != str(binding.authorization_generation)
    ):
        raise DeauthorizationServiceError("event_binding_conflict")
    candidate_digest = candidate_temporal_evidence_digest(snapshot)
    binding_digest = binding_temporal_evidence_digest(candidate_digest, binding.binding_id, binding.binding_version)
    if not hmac.compare_digest(candidate_digest, binding.candidate_evidence_digest) or not hmac.compare_digest(
        binding_digest,
        binding.binding_evidence_digest,
    ):
        raise DeauthorizationServiceError("event_binding_conflict")


def _candidate_snapshot(assertion: VerifiedDeauthorizationAssertion, grant: ZoomOAuthAuthorizationGrant) -> dict:
    claims = assertion.claims
    return {
        "temporal_policy": TEMPORAL_POLICY,
        "zoom_event_at": claims["zoom_event_at"],
        "zoom_request_signed_at": claims["zoom_request_signed_at"],
        "first_verified_at": claims["first_verified_at"],
        "binding_attempt_iat": claims["iat"],
        "attendee_binding_received_at": _utc_iso(assertion.received_at),
        "zoom_event_precision_ms": claims["zoom_event_precision_ms"],
        "zoom_request_precision_ms": claims["zoom_request_precision_ms"],
        "generation_started_at": _utc_iso(grant.generation_started_at),
        "generation_ended_at": _utc_iso(grant.generation_ended_at),
        "client_clock_health_id": claims["client_clock_health_id"],
        "client_clock_continuous": claims["client_clock_continuous"],
        "client_clock_step_free": claims["client_clock_step_free"],
        "client_clock_error_ms": claims["client_clock_error_ms"],
        "attendee_boundary_clock_health_ids": [grant.start_clock_health_id, grant.end_clock_health_id],
        "attendee_boundary_clock_error_ms": [grant.start_clock_error_ms, grant.end_clock_error_ms],
        "attendee_boundary_clock_continuous": [grant.start_clock_continuous, grant.end_clock_continuous],
        "grant_binding_id": str(grant.binding_id),
        "connection_generation": str(grant.authorization_generation),
        "lineage_sequence": grant.grant_sequence,
        "history_complete": grant.lineage.history_complete,
        "has_prior_grant": grant.lineage.has_prior_grant,
    }


def candidate_temporal_evidence_digest(snapshot: dict) -> str:
    # This ordered list is the cross-repository wire contract in revision 4.
    # Additional validated health/error fields remain frozen in the snapshot,
    # but do not silently change this byte-exact digest contract.
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
    return hashlib.sha256(_canonical_json(ordered)).hexdigest()


def binding_temporal_evidence_digest(candidate_digest: str, binding_id, binding_version: int) -> str:
    return hashlib.sha256(_canonical_json([candidate_digest, str(binding_id), binding_version])).hexdigest()


def _fresh_binding_evidence(assertion: VerifiedDeauthorizationAssertion, grant: ZoomOAuthAuthorizationGrant):
    claims = assertion.claims
    times = [claims["zoom_event_at"], claims["zoom_request_signed_at"], claims["first_verified_at"], claims["iat"]]
    if claims["zoom_event_at"] > claims["zoom_request_signed_at"]:
        raise DeauthorizationServiceError("unresolved_temporal_order")
    if max(times) - min(times) > MAX_FRESH_SPAN_SECONDS:
        raise DeauthorizationServiceError("delayed_event_unbound")
    lineage = grant.lineage
    if (
        not lineage.history_complete
        or lineage.has_prior_grant
        or lineage.latest_grant_sequence != 1
        or grant.grant_sequence != 1
        or grant.legacy_history
    ):
        raise DeauthorizationServiceError("unresolved_provider_clock")
    try:
        receipt_clock = configured_clock_evidence()
    except GrantCaptureUnavailable:
        raise DeauthorizationServiceError("clock_untrusted") from None
    boundary_continuous = grant.start_clock_continuous and (
        grant.generation_ended_at is None or grant.end_clock_continuous is True
    )
    boundary_ids = [grant.start_clock_health_id]
    if grant.generation_ended_at is not None:
        boundary_ids.append(grant.end_clock_health_id)
    boundary_error = max(grant.start_clock_error_ms, grant.end_clock_error_ms or 0, receipt_clock.error_ms)
    if (
        not boundary_continuous
        or not grant.start_clock_health_id
        or (grant.generation_ended_at is not None and not grant.end_clock_health_id)
        or any(boundary_id != receipt_clock.health_id for boundary_id in boundary_ids)
        or claims["client_clock_error_ms"] + boundary_error > MAX_COMBINED_CLOCK_ERROR_MS
    ):
        raise DeauthorizationServiceError("clock_untrusted")
    event_at = _datetime_from_epoch(claims["zoom_event_at"])
    lower = event_at - timedelta(seconds=U_SECONDS)
    upper = event_at + timedelta(seconds=U_SECONDS)
    if not grant.generation_started_at < lower:
        raise DeauthorizationServiceError("unresolved_temporal_order")
    if grant.generation_ended_at is not None and not upper < grant.generation_ended_at:
        raise DeauthorizationServiceError("unresolved_temporal_order")
    snapshot = _candidate_snapshot(assertion, grant)
    return snapshot, candidate_temporal_evidence_digest(snapshot)


def _assert_nonce_unused(project, app, assertion):
    receipt = ZoomDeauthorizationAssertionReceipt.objects.select_for_update().filter(
        project=project,
        zoom_oauth_app=app,
        issuer_id=assertion.claims["iss"],
        nonce_digest=assertion.nonce_digest,
    ).first()
    if receipt:
        operation = receipt.operation or (receipt.resolution.operation if receipt.resolution_id else None)
        raise DeauthorizationServiceError(
            "assertion_replayed",
            operation_id=canonical_operation_id(operation) if operation else None,
        )


def _record_receipt(assertion, app, *, operation=None, resolution=None):
    ZoomDeauthorizationAssertionReceipt.objects.create(
        project=app.project,
        zoom_oauth_app=app,
        issuer_id=assertion.claims["iss"],
        key_id=assertion.header["kid"],
        nonce_digest=assertion.nonce_digest,
        claims_digest=assertion.claims_digest,
        purpose=assertion.claims["purpose"],
        binding_mode=assertion.claims["binding_mode"],
        operation=operation,
        resolution=resolution,
        received_at=assertion.received_at,
        expires_at=assertion.received_at + timedelta(days=RECEIPT_RETENTION_DAYS),
    )


def _target_free_resolution(project, app, event_digest, outcome):
    """Freeze an unbound outcome without retaining any caller-supplied target."""

    if outcome not in _TARGET_FREE_OUTCOMES:
        raise ValueError("unsupported target-free deauthorization outcome")
    resolution, _ = ZoomDeauthorizationTargetResolution.objects.get_or_create(
        project=project,
        zoom_oauth_app=app,
        event_digest=event_digest,
        defaults={"outcome": outcome},
    )
    if resolution.outcome != outcome or any(
        value is not None
        for value in (
            resolution.event_binding_id,
            resolution.authorization_grant_id,
            resolution.operation_id,
            resolution.grant_binding_id,
            resolution.connection_digest,
            resolution.authorization_generation,
            resolution.binding_evidence_digest,
        )
    ):
        raise DeauthorizationServiceError("event_binding_conflict")
    return resolution


def _create_event_binding(assertion, app, grant, operation, snapshot, candidate_digest):
    binding_id = uuid.uuid4()
    binding_digest = binding_temporal_evidence_digest(candidate_digest, binding_id, 1)
    return ZoomDeauthorizationEventBinding.objects.create(
        binding_id=binding_id,
        binding_version=1,
        project=app.project,
        zoom_oauth_app=app,
        lineage=grant.lineage,
        authorization_grant=grant,
        operation=operation,
        event_digest=assertion.event_digest,
        app_digest=assertion.app_digest,
        grant_binding_id=grant.binding_id,
        connection_digest=grant.connection_digest,
        authorization_generation=grant.authorization_generation,
        temporal_policy=TEMPORAL_POLICY,
        candidate_evidence_digest=candidate_digest,
        binding_evidence_digest=binding_digest,
        evidence_snapshot=snapshot,
    )


def _grant_operation(grant, proposed_id, *, source):
    operation = grant.canonical_removal_operation
    if operation is not None:
        operation = ZoomRemovalOperation.objects.select_for_update().get(pk=operation.pk)
        try:
            _claim_alternate_identifier(operation, proposed_id)
        except OperationConflict:
            return operation, True
        return operation, False
    if grant.live_connection_id is None:
        raise DeauthorizationServiceError("not_found_unproved")
    try:
        return _get_or_create_operation(
            project=grant.project,
            operation_id=proposed_id,
            operation_type=ZoomRemovalOperationTypes.REVOKE_CONNECTION,
            target_object_id=grant.live_connection.object_id,
            source=source,
            target_generation=grant.authorization_generation,
            authorization_grant=grant,
        ), False
    except OperationConflict as error:
        if error.canonical_operation_id:
            operation = get_project_operation(grant.project, error.canonical_operation_id)
            if operation is not None and operation.authorization_grant_id == grant.pk:
                return operation, True
        raise DeauthorizationServiceError(
            "operation_identifier_conflict",
            operation_id=error.canonical_operation_id,
        ) from None


def _assert_operation_binding(operation, grant, assertion):
    """Require the retained canonical operation to name this exact grant/event."""

    if (
        operation.project_id != grant.project_id
        or operation.operation_type != ZoomRemovalOperationTypes.REVOKE_CONNECTION
        or operation.authorization_grant_id != grant.pk
        or operation.zoom_oauth_app_binding != grant.zoom_oauth_app.deauthorization_binding_id
        or operation.connection_digest != grant.connection_digest
        or operation.target_generation != grant.authorization_generation
        or operation.app_digest != assertion.app_digest
        or (
            operation.verified_deauthorization_event_digest is not None
            and operation.verified_deauthorization_event_digest != assertion.event_digest
        )
    ):
        raise DeauthorizationServiceError(
            "event_binding_conflict",
            operation_id=canonical_operation_id(operation),
        )
    if operation.deauthorization_event_bindings.exclude(
        event_digest=assertion.event_digest
    ).exists():
        raise DeauthorizationServiceError(
            "event_binding_conflict",
            operation_id=canonical_operation_id(operation),
        )


def _resolution_from_binding(project, app, binding):
    if binding.operation_id is None or binding.authorization_grant_id is None:
        outcome = ZoomDeauthorizationResolutionOutcomes.BOUND_EVENT_RESULT_EXPIRED
        defaults = {
            "outcome": outcome,
            "event_binding": binding,
            "grant_binding_id": binding.grant_binding_id,
            "connection_digest": binding.connection_digest,
            "authorization_generation": binding.authorization_generation,
            "binding_evidence_digest": binding.binding_evidence_digest,
        }
    else:
        outcome = ZoomDeauthorizationResolutionOutcomes.RESOLVED_EXISTING_BINDING
        defaults = {
            "outcome": outcome,
            "event_binding": binding,
            "authorization_grant": binding.authorization_grant,
            "operation": binding.operation,
            "grant_binding_id": binding.grant_binding_id,
            "connection_digest": binding.connection_digest,
            "authorization_generation": binding.authorization_generation,
            "binding_evidence_digest": binding.binding_evidence_digest,
        }
    resolution, created = ZoomDeauthorizationTargetResolution.objects.get_or_create(
        project=project,
        zoom_oauth_app=app,
        event_digest=binding.event_digest,
        defaults=defaults,
    )
    if not created and resolution.event_binding_id not in {None, binding.pk}:
        raise DeauthorizationServiceError("event_binding_conflict")
    if not created and resolution.event_binding_id is None and outcome == ZoomDeauthorizationResolutionOutcomes.RESOLVED_EXISTING_BINDING:
        resolution.outcome = outcome
        resolution.event_binding = binding
        resolution.authorization_grant = binding.authorization_grant
        resolution.operation = binding.operation
        resolution.grant_binding_id = binding.grant_binding_id
        resolution.connection_digest = binding.connection_digest
        resolution.authorization_generation = binding.authorization_generation
        resolution.binding_evidence_digest = binding.binding_evidence_digest
        resolution.save()
    return resolution


def resolution_result(resolution):
    result = {"outcome": resolution.outcome, "resolution_id": str(resolution.resolution_id)}
    if resolution.event_binding_id:
        result.update(_binding_recovery(resolution.event_binding))
    if resolution.operation_id:
        snapshot = resolution.event_binding.evidence_snapshot if resolution.event_binding_id else {}
        result.update(
            {
                "operation_id": str(canonical_operation_id(resolution.operation)),
                "zoom_oauth_app_binding": str(resolution.zoom_oauth_app.deauthorization_binding_id),
                "grant_binding_id": str(resolution.grant_binding_id),
                "connection_digest": resolution.connection_digest,
                "connection_generation": str(resolution.authorization_generation),
                "app_digest": hashlib.sha256(str(resolution.zoom_oauth_app.deauthorization_binding_id).encode("ascii")).hexdigest(),
                "generation_started_at": snapshot.get("generation_started_at"),
                "generation_ended_at": snapshot.get("generation_ended_at"),
                "grant_sequence": snapshot.get("lineage_sequence"),
                "grant_history_complete": snapshot.get("history_complete"),
            }
        )
    return result


def resolve_verified_deauthorization(project: Project, assertion: VerifiedDeauthorizationAssertion) -> dict:
    claims = assertion.claims
    with transaction.atomic():
        app = _exact_app(project, assertion)
        _event_lock(project.pk, app.pk, assertion.event_digest)
        _nonce_lock(project.pk, app.pk, assertion.claims["iss"], assertion.nonce_digest)
        _assert_nonce_unused(project, app, assertion)
        binding = (
            ZoomDeauthorizationEventBinding.objects.select_for_update()
            .filter(project=project, zoom_oauth_app=app, event_digest=assertion.event_digest)
            .first()
        )
        existing_resolution = ZoomDeauthorizationTargetResolution.objects.select_for_update().filter(
            project=project,
            zoom_oauth_app=app,
            event_digest=assertion.event_digest,
        ).first()
        if binding:
            _validate_existing_binding_claims(binding, assertion)
            resolution = _resolution_from_binding(project, app, binding)
            _record_receipt(assertion, app, resolution=resolution)
            return resolution_result(resolution)

        if existing_resolution is not None:
            _record_receipt(assertion, app, resolution=existing_resolution)
            return resolution_result(existing_resolution)

        if claims["binding_mode"] == EXISTING_ONLY:
            resolution, _ = ZoomDeauthorizationTargetResolution.objects.get_or_create(
                project=project,
                zoom_oauth_app=app,
                event_digest=assertion.event_digest,
                defaults={"outcome": ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND},
            )
            _record_receipt(assertion, app, resolution=resolution)
            return resolution_result(resolution)

        if not hmac.compare_digest(expected_client_id_digest(claims["zoom_client_id"]), assertion.signer["expected_client_id_digest"]):
            raise DeauthorizationServiceError("scope_not_found", status_code=404)
        identity_digest = provider_identity_digest(project, app, claims["zoom_user_id"], claims["zoom_account_id"])
        lineage = (
            ZoomOAuthAuthorizationLineage.objects.select_for_update()
            .filter(project=project, zoom_oauth_app=app, identity_digest=identity_digest)
            .first()
        )
        if lineage is None:
            resolution = ZoomDeauthorizationTargetResolution.objects.create(
                project=project,
                zoom_oauth_app=app,
                event_digest=assertion.event_digest,
                outcome=ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_NO_MATCH,
            )
            _record_receipt(assertion, app, resolution=resolution)
            return resolution_result(resolution)
        if (
            not lineage.history_complete
            or lineage.has_prior_grant
            or lineage.latest_grant_sequence != 1
        ):
            resolution = ZoomDeauthorizationTargetResolution.objects.create(
                project=project,
                zoom_oauth_app=app,
                event_digest=assertion.event_digest,
                outcome=ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_PROVIDER_CLOCK,
            )
            _record_receipt(assertion, app, resolution=resolution)
            return resolution_result(resolution)
        grants = list(
            ZoomOAuthAuthorizationGrant.objects.select_for_update()
            .filter(project=project, zoom_oauth_app=app, lineage=lineage)
        )
        if len(grants) != 1:
            outcome = (
                ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_NO_MATCH
                if not grants
                else ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_AMBIGUOUS
            )
            resolution = ZoomDeauthorizationTargetResolution.objects.create(
                project=project,
                zoom_oauth_app=app,
                event_digest=assertion.event_digest,
                outcome=outcome,
            )
            _record_receipt(assertion, app, resolution=resolution)
            return resolution_result(resolution)
        grant = grants[0]
        try:
            snapshot, candidate_digest = _fresh_binding_evidence(assertion, grant)
        except DeauthorizationServiceError as error:
            outcome = error.code if error.code in ZoomDeauthorizationResolutionOutcomes.values else ZoomDeauthorizationResolutionOutcomes.UNRESOLVED_PROVIDER_CLOCK
            resolution = ZoomDeauthorizationTargetResolution.objects.create(
                project=project,
                zoom_oauth_app=app,
                event_digest=assertion.event_digest,
                outcome=outcome,
            )
            _record_receipt(assertion, app, resolution=resolution)
            return resolution_result(resolution)

        operation, _identifier_conflict = _grant_operation(
            grant,
            uuid.uuid4(),
            source=ZoomRemovalOperationSources.ZOOM_DEAUTHORIZATION,
        )
        _assert_operation_binding(operation, grant, assertion)
        binding = _create_event_binding(assertion, app, grant, operation, snapshot, candidate_digest)
        resolution = ZoomDeauthorizationTargetResolution.objects.create(
            project=project,
            zoom_oauth_app=app,
            event_digest=assertion.event_digest,
            outcome=ZoomDeauthorizationResolutionOutcomes.RESOLVED,
            event_binding=binding,
            authorization_grant=grant,
            operation=operation,
            grant_binding_id=grant.binding_id,
            connection_digest=grant.connection_digest,
            authorization_generation=grant.authorization_generation,
            binding_evidence_digest=binding.binding_evidence_digest,
        )
        _record_receipt(assertion, app, resolution=resolution)
        return resolution_result(resolution)


def _settle_operation(operation, grant, binding, assertion):
    now = database_clock_now()
    operation = ZoomRemovalOperation.objects.select_for_update().get(pk=operation.pk)
    operation.lease_token = None
    operation.lease_expires_at = None
    connection = None
    if grant.live_connection_id:
        connection = (
            ZoomOAuthConnection.objects.select_for_update()
            .filter(
                pk=grant.live_connection_id,
                zoom_oauth_app=grant.zoom_oauth_app,
                authorization_generation=grant.authorization_generation,
            )
            .first()
        )
        if connection is None:
            raise DeauthorizationServiceError("generation_mismatch")
        if connection.state != ZoomOAuthConnectionStates.REMOVING:
            connection.state = ZoomOAuthConnectionStates.REMOVING
            connection.save(update_fields=["state", "updated_at"])
        WebhookDeliveryAttempt.objects.filter(zoom_oauth_connection=connection).delete()
        connection_pk = connection.pk
        connection.delete()
        if ZoomOAuthConnection.objects.filter(pk=connection_pk).exists():
            raise DeauthorizationServiceError("local_delete_unproved")
    operation.state = ZoomRemovalOperationStates.REVOKED
    operation.phase = ZoomRemovalOperationPhases.COMPLETE
    operation.failure_code = None
    operation.target_object_id = None
    operation.storage_manifest = {}
    _assert_operation_binding(operation, grant, assertion)
    operation.signed_deauthorization_settled_at = operation.signed_deauthorization_settled_at or now
    operation.verified_deauthorization_at = operation.verified_deauthorization_at or _datetime_from_epoch(assertion.claims["zoom_event_at"])
    operation.verified_deauthorization_event_digest = operation.verified_deauthorization_event_digest or assertion.event_digest
    operation.completed_at = operation.completed_at or now
    operation.expires_at = now + timedelta(days=RECEIPT_RETENTION_DAYS)
    operation.terminal_basis = "provider_and_signed" if operation.provider_revoke_settled_at else "signed_zoom_deauthorization"
    operation.save()
    binding.terminal_state = operation.state
    binding.terminal_result_digest = hashlib.sha256(
        _canonical_json(
            [
                str(canonical_operation_id(operation)),
                operation.state,
                operation.terminal_basis,
                str(binding.binding_id),
                binding.binding_evidence_digest,
            ]
        )
    ).hexdigest()
    binding.save(update_fields=["terminal_state", "terminal_result_digest", "updated_at"])
    return operation


def settle_verified_deauthorization(project: Project, assertion: VerifiedDeauthorizationAssertion) -> dict:
    claims = assertion.claims
    with transaction.atomic():
        app = _exact_app(project, assertion)
        _event_lock(project.pk, app.pk, assertion.event_digest)
        _nonce_lock(project.pk, app.pk, assertion.claims["iss"], assertion.nonce_digest)
        _assert_nonce_unused(project, app, assertion)
        binding = (
            ZoomDeauthorizationEventBinding.objects.select_for_update()
            .filter(project=project, zoom_oauth_app=app, event_digest=assertion.event_digest)
            .first()
        )
        unresolved_resolution = ZoomDeauthorizationTargetResolution.objects.select_for_update().filter(
            project=project,
            zoom_oauth_app=app,
            event_digest=assertion.event_digest,
            event_binding__isnull=True,
        ).first()
        if binding is None and unresolved_resolution is not None:
            raise DeauthorizationServiceError(unresolved_resolution.outcome)
        if binding and claims["binding_mode"] == CREATE_IF_FRESH:
            if (
                str(binding.grant_binding_id) != claims["grant_binding_id"]
                or binding.connection_digest != claims["connection_digest"]
                or str(binding.authorization_generation) != claims["connection_generation"]
            ):
                raise DeauthorizationServiceError("event_binding_conflict")
            raise DeauthorizationServiceError("binding_already_exists", recovery=_binding_recovery(binding))
        if binding is None and claims["binding_mode"] == EXISTING_ONLY:
            _target_free_resolution(
                project,
                app,
                assertion.event_digest,
                ZoomDeauthorizationResolutionOutcomes.DELAYED_EVENT_UNBOUND,
            )
            return CommittedDeauthorizationError(code="delayed_event_unbound")
        if binding is None and "resolution_id" in claims:
            raise DeauthorizationServiceError("resolution_mismatch")

        if binding:
            _validate_existing_binding_claims(binding, assertion)
            if claims["temporal_evidence_digest"] != binding.binding_evidence_digest:
                raise DeauthorizationServiceError("temporal_evidence_mismatch")
            if (
                str(binding.grant_binding_id) != claims["grant_binding_id"]
                or binding.connection_digest != claims["connection_digest"]
                or str(binding.authorization_generation) != claims["connection_generation"]
            ):
                raise DeauthorizationServiceError("event_binding_conflict")
            lineage = ZoomOAuthAuthorizationLineage.objects.select_for_update().filter(
                pk=binding.lineage_id,
                project=project,
                zoom_oauth_app=app,
            ).first()
            if lineage is None:
                raise DeauthorizationServiceError("event_binding_conflict")
            grant = ZoomOAuthAuthorizationGrant.objects.select_for_update().filter(
                pk=binding.authorization_grant_id,
                lineage=lineage,
                project=project,
                zoom_oauth_app=app,
            ).first()
            operation = ZoomRemovalOperation.objects.select_for_update().filter(pk=binding.operation_id).first()
            if grant is None or operation is None:
                raise DeauthorizationServiceError("bound_event_result_expired")
            _assert_operation_binding(operation, grant, assertion)
            resolution = (
                ZoomDeauthorizationTargetResolution.objects.select_for_update()
                .filter(
                    project=project,
                    zoom_oauth_app=app,
                    event_binding=binding,
                    authorization_grant=grant,
                    operation=operation,
                )
                .first()
            )
            claimed_resolution = claims.get("resolution_id")
            if (resolution is None and claimed_resolution is not None) or (
                resolution is not None
                and claimed_resolution != str(resolution.resolution_id)
            ):
                raise DeauthorizationServiceError("resolution_mismatch")
            try:
                _claim_alternate_identifier(operation, uuid.UUID(claims["operation_id"]))
            except OperationConflict:
                _record_receipt(assertion, app, operation=operation)
                return CommittedDeauthorizationError(
                    code="operation_identifier_conflict",
                    operation_id=canonical_operation_id(operation),
                )
        else:
            candidate = ZoomOAuthAuthorizationGrant.objects.filter(
                project=project,
                zoom_oauth_app=app,
                binding_id=claims["grant_binding_id"],
                connection_digest=claims["connection_digest"],
                authorization_generation=claims["connection_generation"],
            ).values("pk", "lineage_id").first()
            if candidate is None:
                raise DeauthorizationServiceError("scope_not_found", status_code=404)
            lineage = ZoomOAuthAuthorizationLineage.objects.select_for_update().filter(
                pk=candidate["lineage_id"],
                project=project,
                zoom_oauth_app=app,
            ).first()
            grant = ZoomOAuthAuthorizationGrant.objects.select_for_update().filter(
                pk=candidate["pk"],
                lineage=lineage,
                project=project,
                zoom_oauth_app=app,
                binding_id=claims["grant_binding_id"],
                connection_digest=claims["connection_digest"],
                authorization_generation=claims["connection_generation"],
            ).first()
            if lineage is None or grant is None:
                raise DeauthorizationServiceError("scope_not_found", status_code=404)
            try:
                snapshot, candidate_digest = _fresh_binding_evidence(assertion, grant)
            except DeauthorizationServiceError as error:
                if error.code not in _TARGET_FREE_OUTCOMES:
                    raise
                _target_free_resolution(project, app, assertion.event_digest, error.code)
                return CommittedDeauthorizationError(code=error.code)
            if claims["temporal_evidence_digest"] != candidate_digest:
                raise DeauthorizationServiceError("temporal_evidence_mismatch")
            operation, identifier_conflict = _grant_operation(
                grant,
                uuid.UUID(claims["operation_id"]),
                source=ZoomRemovalOperationSources.ZOOM_DEAUTHORIZATION,
            )
            if identifier_conflict:
                _record_receipt(assertion, app, operation=operation)
                return CommittedDeauthorizationError(
                    code="operation_identifier_conflict",
                    operation_id=canonical_operation_id(operation),
                )
            _assert_operation_binding(operation, grant, assertion)
            binding = _create_event_binding(assertion, app, grant, operation, snapshot, candidate_digest)

        operation = _settle_operation(operation, grant, binding, assertion)
        _record_receipt(assertion, app, operation=operation)
        result = operation_result(operation)
        result.update(_binding_recovery(binding))
        return result
