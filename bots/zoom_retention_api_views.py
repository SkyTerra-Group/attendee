import uuid

from django.conf import settings
from django.http import Http404
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response

from .authentication import ApiKeyAuthentication
from .models import Bot, ZoomRemovalOperationSources
from .throttling import ProjectPostThrottle
from .zoom_deauthorization import (
    CommittedDeauthorizationError,
    DeauthorizationServiceError,
    resolve_verified_deauthorization,
    settle_verified_deauthorization,
)
from .zoom_deauthorization_assertion import (
    MAX_ASSERTION_BYTES,
    RESOLVE_PURPOSE,
    SETTLE_PURPOSE,
    AssertionRejected,
    verify_deauthorization_assertion,
)
from .zoom_deauthorization_grants import database_clock_now
from .zoom_retention import (
    MAX_PURGE_TARGETS,
    HISTORICAL_GRANT_CLEANUP_PURPOSE,
    CrossProjectTarget,
    HistoricalGrantIneligible,
    OperationConflict,
    UntrustedDeauthorizationSource,
    get_project_operation,
    operation_result,
    process_bot_purge,
    process_connection_revoke,
    process_historical_grant_cleanup,
)


def _require_enabled():
    if not settings.ENABLE_ZOOM_RETENTION_REMOVAL_API:
        raise Http404


def _uuid(value):
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


def _valid_target_id(value, prefix):
    return isinstance(value, str) and value.startswith(prefix) and len(value) <= 32


def _scope_is_valid(request):
    return isinstance(request.data, dict) and request.data.get("project_id") == request.auth.project.object_id


def _safe_conflict_response(error):
    body = {"error": "operation_conflict"}
    if error.canonical_operation_id:
        body["canonical_operation_id"] = str(error.canonical_operation_id)
    return Response(body, status=status.HTTP_409_CONFLICT)


def _signed_error_response(error):
    body = {"error": error.code}
    if error.operation_id:
        body["operation_id"] = str(error.operation_id)
    body.update(error.recovery or {})
    return Response(body, status=error.status_code)


def _verified_assertion(request, purpose):
    try:
        content_length = int(request.META.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        raise AssertionRejected("invalid_request") from None
    if content_length <= 0 or content_length > MAX_ASSERTION_BYTES:
        raise AssertionRejected("invalid_request")
    if type(request.data) is not dict or set(request.data) != {"assertion"}:
        raise AssertionRejected("invalid_request")
    received_at = database_clock_now()
    return verify_deauthorization_assertion(
        request.data["assertion"],
        project=request.auth.project,
        purpose=purpose,
        received_at=received_at,
    )


class ZoomSignedDeauthorizationView(GenericAPIView):
    authentication_classes = [ApiKeyAuthentication]
    throttle_classes = [ProjectPostThrottle]

    def post(self, request):
        _require_enabled()
        try:
            assertion = _verified_assertion(request, SETTLE_PURPOSE)
            result = settle_verified_deauthorization(request.auth.project, assertion)
        except AssertionRejected as error:
            return Response({"error": error.code}, status=status.HTTP_401_UNAUTHORIZED)
        except DeauthorizationServiceError as error:
            return _signed_error_response(error)
        if isinstance(result, CommittedDeauthorizationError):
            return _signed_error_response(result)
        return Response(result, status=status.HTTP_200_OK)


class ZoomSignedDeauthorizationResolveView(GenericAPIView):
    authentication_classes = [ApiKeyAuthentication]
    throttle_classes = [ProjectPostThrottle]

    def post(self, request):
        _require_enabled()
        try:
            assertion = _verified_assertion(request, RESOLVE_PURPOSE)
            result = resolve_verified_deauthorization(request.auth.project, assertion)
        except AssertionRejected as error:
            return Response({"error": error.code}, status=status.HTTP_401_UNAUTHORIZED)
        except DeauthorizationServiceError as error:
            return _signed_error_response(error)
        return Response(result, status=status.HTTP_200_OK)


class ZoomConnectionRevokeView(GenericAPIView):
    authentication_classes = [ApiKeyAuthentication]
    throttle_classes = [ProjectPostThrottle]

    def post(self, request):
        _require_enabled()
        if not _scope_is_valid(request):
            return Response({"error": "scope_not_found"}, status=status.HTTP_404_NOT_FOUND)

        operation_id = _uuid(request.data.get("operation_id"))
        connection_id = request.data.get("connection_id")
        source = request.data.get("source")
        if operation_id is None or not _valid_target_id(connection_id, "zoc_") or source != ZoomRemovalOperationSources.SKYTERRA_INITIATED:
            return Response({"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            operation = process_connection_revoke(
                project=request.auth.project,
                operation_id=operation_id,
                connection_object_id=connection_id,
                source=source,
            )
        except CrossProjectTarget:
            return Response({"error": "scope_not_found"}, status=status.HTTP_404_NOT_FOUND)
        except OperationConflict as error:
            return _safe_conflict_response(error)
        except UntrustedDeauthorizationSource:
            return Response({"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(operation_result(operation), status=status.HTTP_200_OK)


_HISTORICAL_GRANT_CLEANUP_FIELDS = frozenset(
    {
        "project_id",
        "operation_id",
        "zoom_oauth_app_binding",
        "grant_binding_id",
        "authorization_generation",
        "source",
        "purpose",
        "authorization_ref",
    }
)


class ZoomHistoricalGrantCleanupView(GenericAPIView):
    """Separately authorized cleanup receipt for one exact closed grant.

    Never binds or settles a Zoom deauthorization event and never claims a
    remote OAuth revoke; see ``process_historical_grant_cleanup``.
    """

    authentication_classes = [ApiKeyAuthentication]
    throttle_classes = [ProjectPostThrottle]

    def post(self, request):
        _require_enabled()
        if not _scope_is_valid(request):
            return Response({"error": "scope_not_found"}, status=status.HTTP_404_NOT_FOUND)
        if set(request.data.keys()) != _HISTORICAL_GRANT_CLEANUP_FIELDS:
            return Response({"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST)
        values = {
            name: _uuid(request.data.get(name))
            for name in ("operation_id", "zoom_oauth_app_binding", "grant_binding_id", "authorization_generation", "authorization_ref")
        }
        if (
            any(value is None for value in values.values())
            or request.data.get("source") != ZoomRemovalOperationSources.SKYTERRA_INITIATED
            or request.data.get("purpose") != HISTORICAL_GRANT_CLEANUP_PURPOSE
        ):
            return Response({"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            operation = process_historical_grant_cleanup(project=request.auth.project, **values)
        except CrossProjectTarget:
            return Response({"error": "scope_not_found"}, status=status.HTTP_404_NOT_FOUND)
        except HistoricalGrantIneligible as error:
            return Response({"error": error.code}, status=status.HTTP_409_CONFLICT)
        except OperationConflict as error:
            return _safe_conflict_response(error)
        return Response(operation_result(operation), status=status.HTTP_200_OK)


class ZoomBotPurgeView(GenericAPIView):
    authentication_classes = [ApiKeyAuthentication]
    throttle_classes = [ProjectPostThrottle]

    def post(self, request):
        _require_enabled()
        if not _scope_is_valid(request):
            return Response({"error": "scope_not_found"}, status=status.HTTP_404_NOT_FOUND)

        targets = request.data.get("targets")
        if not isinstance(targets, list) or not targets or len(targets) > MAX_PURGE_TARGETS:
            return Response({"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST)

        normalized = []
        operation_ids = set()
        bot_ids = set()
        for target in targets:
            if not isinstance(target, dict):
                return Response({"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST)
            operation_id = _uuid(target.get("operation_id"))
            bot_id = target.get("bot_id")
            if operation_id is None or not _valid_target_id(bot_id, "bot_") or operation_id in operation_ids or bot_id in bot_ids:
                return Response({"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST)
            operation_ids.add(operation_id)
            bot_ids.add(bot_id)
            normalized.append((operation_id, bot_id))

        # Preflight the entire bounded batch so a cross-project target cannot
        # produce a receipt or leave earlier entries partially processed.
        if Bot.objects.filter(object_id__in=bot_ids).exclude(project=request.auth.project).exists():
            return Response({"error": "scope_not_found"}, status=status.HTTP_404_NOT_FOUND)

        results = []
        for operation_id, bot_id in normalized:
            try:
                operation = process_bot_purge(project=request.auth.project, operation_id=operation_id, bot_object_id=bot_id)
            except CrossProjectTarget:
                return Response({"error": "scope_not_found"}, status=status.HTTP_404_NOT_FOUND)
            except OperationConflict as error:
                return _safe_conflict_response(error)
            results.append(operation_result(operation))
        return Response({"results": results}, status=status.HTTP_200_OK)


class ZoomRemovalOperationDetailView(GenericAPIView):
    authentication_classes = [ApiKeyAuthentication]

    def get(self, request, operation_id):
        _require_enabled()
        operation = get_project_operation(request.auth.project, operation_id)
        if operation is None:
            return Response({"error": "operation_not_found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(operation_result(operation), status=status.HTTP_200_OK)
