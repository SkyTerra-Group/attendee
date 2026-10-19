import base64
import logging
import uuid

import requests
from django.conf import settings
from django.db import IntegrityError, transaction

from attendee.logging import bounded_exception_metadata, log_bounded_exception

from .models import (
    ZoomOAuthApp,
    ZoomOAuthAuthorizationGrant,
    ZoomOAuthConnection,
    ZoomOAuthConnectionStates,
)
from .serializers import CreateZoomOAuthConnectionSerializer
from .zoom_deauthorization_grants import (
    GrantCaptureUnavailable,
    capture_authorization_grant,
    close_authorization_grant_for_replacement,
    valid_provider_identity_component,
)
from .zoom_deauthorization_readiness import DeauthorizationReadinessError, assert_capture_ready

logger = logging.getLogger(__name__)


def _get_user_info(access_token: str) -> dict:
    # Step 1 – who is the user?
    resp = requests.get("https://api.zoom.us/v2/users/me", headers={"Authorization": f"Bearer {access_token}"}, timeout=10)
    resp.raise_for_status()
    return resp.json()  # {id, first_name, last_name, email}


def _exchange_access_code_for_tokens(code: str, redirect_uri: str, client_id: str, client_secret: str) -> dict:
    """POST the authorization code to /oauth/token to get access & refresh."""
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    headers = {"Authorization": f"Basic {basic}"}
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    resp = requests.post("https://zoom.us/oauth/token", headers=headers, data=data, timeout=10)
    resp.raise_for_status()
    return resp.json()  # {access_token, refresh_token, expires_in, …}


def create_zoom_oauth_connection(data, project):
    """
    Create a new zoom oauth connection for the given project.

    Args:
        data: Dictionary containing zoom oauth connection creation data
        project: Project instance to associate the zoom oauth connection with

    Returns:
        tuple: (zoom_oauth_connection_instance, error_dict)
               Returns (ZoomOAuthConnection, None) on success
               Returns (None, error_dict) on failure
    """
    # Validate the input data
    serializer = CreateZoomOAuthConnectionSerializer(data=data)
    if not serializer.is_valid():
        return None, serializer.errors

    validated_data = serializer.validated_data

    # Validate that the Zoom OAuth App exists in the project
    zoom_oauth_app = None
    try:
        if validated_data["zoom_oauth_app_binding"]:
            zoom_oauth_app = ZoomOAuthApp.objects.get(
                deauthorization_binding_id=validated_data["zoom_oauth_app_binding"],
                project=project,
            )
            if validated_data["zoom_oauth_app_id"] and validated_data["zoom_oauth_app_id"] != zoom_oauth_app.object_id:
                return None, {"error": "Zoom OAuth App scope mismatch."}
        elif validated_data["zoom_oauth_app_id"]:
            zoom_oauth_app = ZoomOAuthApp.objects.get(object_id=validated_data["zoom_oauth_app_id"], project=project)
        else:
            zoom_oauth_app = ZoomOAuthApp.objects.get(project=project)
    except ZoomOAuthApp.DoesNotExist:
        return None, {"error": "Zoom OAuth App was not found in the authenticated project."}

    # Once exact capture is enabled, or an app has an explicit clean-history
    # baseline, a legacy callback would create untracked authorization history
    # and could later masquerade as a complete sequence-one identity.
    if not validated_data["zoom_oauth_app_binding"] and (
        settings.ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE
        or not zoom_oauth_app.legacy_history_unknown
    ):
        return None, {"error": "Exact Zoom OAuth app binding is required."}

    # An exact binding is an explicit request to participate in signed
    # deauthorization history. Reject it before any provider exchange unless
    # the independent capture gate and all DB-backed prerequisites are ready.
    if validated_data["zoom_oauth_app_binding"]:
        try:
            assert_capture_ready(zoom_oauth_app)
        except DeauthorizationReadinessError:
            return None, {"error": "Zoom authorization lineage could not be recorded safely."}

    # Exchange the access code for tokens
    zoom_oauth_tokens = None
    try:
        zoom_oauth_tokens = _exchange_access_code_for_tokens(
            code=validated_data["authorization_code"],
            redirect_uri=validated_data["redirect_uri"],
            client_id=zoom_oauth_app.client_id,
            client_secret=zoom_oauth_app.client_secret,
        )
    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_oauth_authorization_failed",
            "token_exchange_failed",
            error,
        )
        return None, {"error": "Error exchanging access code for tokens. Please check that the authorization code and redirect URI are correct."}

    # Validate that the tokens have the required scopes
    scopes_for_token = zoom_oauth_tokens.get("scope", "").split(" ")

    # Minimum scopes depends on what the capabilities of the zoom oauth connection are.
    minimum_scopes_for_token = []
    if validated_data.get("is_local_recording_token_supported"):
        minimum_scopes_for_token.extend(["user:read:user", "user:read:zak", "meeting:read:list_meetings", "meeting:read:local_recording_token"])
    if validated_data.get("is_onbehalf_token_supported"):
        minimum_scopes_for_token.extend(["user:read:user", "user:read:token"])
    # Uniqify the scopes
    minimum_scopes_for_token = list(set(minimum_scopes_for_token))

    missing_scopes = [scope for scope in minimum_scopes_for_token if scope not in scopes_for_token]
    if missing_scopes:
        return None, {"error": f"The authorization is missing the following required scopes: {missing_scopes}."}

    # Get the user info
    user_info = None
    try:
        user_info = _get_user_info(zoom_oauth_tokens["access_token"])
    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_oauth_authorization_failed",
            "user_info_failed",
            error,
        )
        return None, {"error": "Error getting user info. Please check that the access token is valid."}

    # Validate that the user is active
    if type(user_info) is not dict or user_info.get("status") != "active":
        return None, {"error": "The user is not active."}
    if not valid_provider_identity_component(
        user_info.get("id")
    ) or not valid_provider_identity_component(user_info.get("account_id")):
        logger.error("zoom_oauth_authorization_failed code=provider_identity_invalid")
        return None, {"error": "Zoom returned an invalid user identity."}

    try:
        with transaction.atomic():
            # Shared signed-deauthorization lock order begins with the exact
            # app before any connection/lineage row. This prevents a callback
            # from holding the connection while settlement holds the app.
            zoom_oauth_app = ZoomOAuthApp.objects.select_for_update().get(
                pk=zoom_oauth_app.pk,
                project=project,
            )
            # Re-evaluate eligibility under the same app lock used by capture.
            # A recovery/baseline transaction may have changed the barrier
            # while this callback was waiting on provider I/O.
            if not validated_data["zoom_oauth_app_binding"] and (
                settings.ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE
                or not zoom_oauth_app.legacy_history_unknown
            ):
                return None, {"error": "Exact Zoom OAuth app binding is required."}
            if validated_data["zoom_oauth_app_binding"]:
                try:
                    assert_capture_ready(zoom_oauth_app)
                except DeauthorizationReadinessError:
                    return None, {
                        "error": "Zoom authorization lineage could not be recorded safely."
                    }
            zoom_oauth_connection = ZoomOAuthConnection.objects.select_for_update().filter(zoom_oauth_app=zoom_oauth_app, user_id=user_info["id"]).first()
            created = zoom_oauth_connection is None
            replacement_boundary = None
            if created:
                zoom_oauth_connection = ZoomOAuthConnection.objects.create(
                    zoom_oauth_app=zoom_oauth_app,
                    user_id=user_info["id"],
                    account_id=user_info["account_id"],
                )
            elif validated_data["zoom_oauth_app_binding"]:
                # The DB forbids identity/generation changes while a grant is
                # live. Close that exact interval first, then capture the new
                # generation later in this same transaction.
                replacement_boundary = close_authorization_grant_for_replacement(
                    zoom_oauth_connection
                )
            elif ZoomOAuthAuthorizationGrant.objects.filter(
                live_connection=zoom_oauth_connection
            ).exists():
                return None, {"error": "Exact Zoom OAuth app binding is required."}

            zoom_oauth_connection.account_id = user_info["account_id"]
            zoom_oauth_connection.metadata = validated_data["metadata"]

            # Set the capabilities
            zoom_oauth_connection.is_local_recording_token_supported = validated_data.get("is_local_recording_token_supported")
            zoom_oauth_connection.is_onbehalf_token_supported = validated_data.get("is_onbehalf_token_supported")

            # Set the state to connected
            zoom_oauth_connection.state = ZoomOAuthConnectionStates.CONNECTED
            zoom_oauth_connection.connection_failure_data = None

            credentials = {"refresh_token": zoom_oauth_tokens["refresh_token"]}
            if created:
                zoom_oauth_connection.set_credentials(credentials)
            else:
                # A real authorization-code exchange is the trust boundary for
                # a new grant. Advance its generation atomically so an older
                # ambiguous removal cannot delete or rewrite it.
                zoom_oauth_connection.replace_authorization_credentials(credentials)

            # Exact-app callers participate in the permanent grant lineage.
            # Legacy callers remain compatible but cannot later gain time-only
            # signed-event authority from incomplete history.
            if validated_data["zoom_oauth_app_binding"]:
                capture_authorization_grant(
                    zoom_oauth_connection,
                    replacement_boundary=replacement_boundary,
                )

            return zoom_oauth_connection, None

    except GrantCaptureUnavailable:
        return None, {"error": "Zoom authorization lineage could not be recorded safely."}
    except IntegrityError as error:
        error_id = str(uuid.uuid4())
        exception_class, status_class = bounded_exception_metadata(error)
        logger.error(
            "zoom_oauth_authorization_failed code=database_conflict error_id=%s exception_class=%s http_status_class=%s",
            error_id,
            exception_class,
            status_class,
        )
        return None, {"non_field_errors": ["An error occurred while creating the zoom oauth connection. Error ID: " + error_id]}
    except Exception as error:
        error_id = str(uuid.uuid4())
        exception_class, status_class = bounded_exception_metadata(error)
        logger.error(
            "zoom_oauth_authorization_failed code=internal_error error_id=%s exception_class=%s http_status_class=%s",
            error_id,
            exception_class,
            status_class,
        )
        return None, {"non_field_errors": ["An unexpected error occurred while creating the zoom oauth connection. Error ID: " + error_id]}
