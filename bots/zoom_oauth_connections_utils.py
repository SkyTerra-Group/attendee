import hashlib
import hmac
import logging

import requests
from django.db import transaction
from django.utils import timezone

from attendee.logging import log_bounded_exception
from bots.meeting_url_utils import parse_zoom_join_url
from bots.models import Bot, WebhookTriggerTypes, ZoomMeetingToZoomOAuthConnectionMapping, ZoomOAuthConnection, ZoomOAuthConnectionStates
from bots.webhook_payloads import zoom_oauth_connection_webhook_payload
from bots.webhook_utils import trigger_webhook

logger = logging.getLogger(__name__)


class ZoomAPIError(Exception):
    """Custom exception for Zoom API errors."""

    pass


class ZoomAPIAuthenticationError(ZoomAPIError):
    """Custom exception for Zoom API errors."""

    pass


class ZoomOAuthConnectionRemovalFenced(ZoomAPIError):
    """Raised when work targets an authorization generation being removed."""


def _assert_zoom_oauth_connection_writable(zoom_oauth_connection: ZoomOAuthConnection) -> None:
    if (
        not ZoomOAuthConnection.objects.filter(
            pk=zoom_oauth_connection.pk,
            authorization_generation=zoom_oauth_connection.authorization_generation,
        )
        .exclude(state=ZoomOAuthConnectionStates.REMOVING)
        .exists()
    ):
        raise ZoomOAuthConnectionRemovalFenced()


def _locked_writable_zoom_oauth_connection(zoom_oauth_connection: ZoomOAuthConnection) -> ZoomOAuthConnection:
    current = ZoomOAuthConnection.objects.select_for_update().select_related("zoom_oauth_app").filter(pk=zoom_oauth_connection.pk, authorization_generation=zoom_oauth_connection.authorization_generation).first()
    if current is None or current.state == ZoomOAuthConnectionStates.REMOVING:
        raise ZoomOAuthConnectionRemovalFenced()
    return current


def update_zoom_oauth_connection_if_writable(zoom_oauth_connection: ZoomOAuthConnection, **values) -> ZoomOAuthConnection:
    """Apply a worker result under the authorization-generation fence."""

    with transaction.atomic():
        current = _locked_writable_zoom_oauth_connection(zoom_oauth_connection)
        for field, value in values.items():
            setattr(current, field, value)
        current.save(update_fields=[*values.keys(), "updated_at"])
        return current


def client_id_and_secret_is_valid(client_id: str, client_secret: str) -> bool:
    """
    Validate Zoom OAuth client credentials without requiring a user via client_credentials grant type

    Returns:
        True if the credentials are valid, False otherwise
    """
    try:
        response = requests.post("https://zoom.us/oauth/token", auth=(client_id, client_secret), data={"grant_type": "client_credentials"}, timeout=30)

        # If we get a 200  the credentials are valid
        if response.status_code == 200:
            return True

        return False
    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_oauth_credentials_validation_failed",
            "transport_or_parse_error",
            error,
        )
        return False


def _verify_zoom_webhook_signature(body: str, timestamp: str, signature: str, secret: str):
    """Verify the Zoom webhook signature."""
    hmac_hash = hmac.new(secret.encode("utf-8"), f"v0:{timestamp}:{body}".encode("utf-8"), hashlib.sha256).hexdigest()
    expected_signature = f"v0={hmac_hash}"
    return hmac.compare_digest(expected_signature, signature or "")


def compute_zoom_webhook_validation_response(plain_token: str, secret_token: str) -> dict:
    """
    Compute the response for a Zoom webhook validation request.

    Zoom sends a challenge-response validation request when setting up a webhook endpoint.
    This function creates the required HMAC SHA-256 hash of the plainToken using the
    webhook secret token.

    Args:
        plain_token: The plainToken value from the webhook request payload
        secret_token: The webhook secret token configured in Zoom

    Returns:
        dict: A dictionary containing 'plainToken' and 'encryptedToken' keys
        Example: {
            "plainToken": "qgg8vlvZRS6UYooatFL8Aw",
            "encryptedToken": "23a89b634c017e5364a1c8d9c8ea909b60dd5599e2bb04bb1558d9c3a121faa5"
        }
    """
    # Create HMAC SHA-256 hash with secret_token as salt and plain_token as the string to hash
    encrypted_token = hmac.new(secret_token.encode("utf-8"), plain_token.encode("utf-8"), hashlib.sha256).hexdigest()

    return {"plainToken": plain_token, "encryptedToken": encrypted_token}


def _raise_if_error_is_authentication_error(e: requests.RequestException):
    try:
        payload = e.response.json() if e.response is not None else {}
    except (TypeError, ValueError):
        payload = {}
    error_code = payload.get("error") if isinstance(payload, dict) else None
    if error_code == "invalid_grant" or error_code == "invalid_client":
        raise ZoomAPIAuthenticationError("zoom_authentication_rejected")

    return


def _get_access_token(zoom_oauth_connection) -> str:
    """
    Exchange the stored refresh token for a new access token.
    Zoom returns a new refresh_token on each successful refresh.
    Persist it so we don't lose the chain.
    """
    _assert_zoom_oauth_connection_writable(zoom_oauth_connection)
    credentials = zoom_oauth_connection.get_credentials()
    if not credentials:
        raise ZoomAPIAuthenticationError("zoom_credentials_unavailable")

    refresh_token = credentials.get("refresh_token")
    client_id = zoom_oauth_connection.zoom_oauth_app.client_id
    client_secret = zoom_oauth_connection.zoom_oauth_app.client_secret
    if not refresh_token or not client_id or not client_secret:
        raise ZoomAPIAuthenticationError("zoom_credentials_incomplete")

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    try:
        response = requests.post("https://zoom.us/oauth/token", data=data, timeout=30)
        response.raise_for_status()
        token_data = response.json()

        access_token = token_data.get("access_token")
        if not access_token:
            raise ZoomAPIError("zoom_refresh_access_token_missing")

        # IMPORTANT: Zoom rotates refresh tokens. Save the new one if provided.
        new_refresh = token_data.get("refresh_token")
        if new_refresh and new_refresh != refresh_token:
            with transaction.atomic():
                current = _locked_writable_zoom_oauth_connection(zoom_oauth_connection)
                current_credentials = current.get_credentials() or {}
                current_credentials["refresh_token"] = new_refresh
                current.set_credentials(current_credentials)
            logger.info("zoom_oauth_refresh_rotated")

        _assert_zoom_oauth_connection_writable(zoom_oauth_connection)
        return access_token

    except requests.RequestException as error:
        _raise_if_error_is_authentication_error(error)
        log_bounded_exception(
            logger,
            "zoom_oauth_refresh_failed",
            "provider_request_failed",
            error,
        )
        raise ZoomAPIError("zoom_refresh_failed") from None


def _make_zoom_api_request(url: str, access_token: str, params: dict) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}

    req = requests.Request("GET", url, headers=headers, params=params).prepare()
    try:
        # Send the request
        with requests.Session() as s:
            resp = s.send(req, timeout=25)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as error:
        _raise_if_error_is_authentication_error(error)
        log_bounded_exception(
            logger,
            "zoom_api_request_failed",
            "provider_request_failed",
            error,
        )
        raise ZoomAPIError("zoom_api_request_failed") from None


def _get_zoom_personal_meeting_id(access_token: str) -> str:
    base_url = "https://api.zoom.us/v2/users/me"
    response_data = _make_zoom_api_request(base_url, access_token, {})
    return response_data.get("pmi")


def _get_local_recording_token(meeting_id: str, access_token: str) -> str:
    base_url = f"https://api.zoom.us/v2/meetings/{meeting_id}/jointoken/local_recording?bypass_waiting_room=true"

    response_data = _make_zoom_api_request(base_url, access_token, {})
    return response_data.get("token")


def _get_onbehalf_token(meeting_id: str, access_token: str) -> str:
    base_url = f"https://api.zoom.us/v2/users/me/token?type=onbehalf&meeting_id={meeting_id}"
    response_data = _make_zoom_api_request(base_url, access_token, {})
    return response_data.get("token")


def _get_zoom_meetings(access_token: str) -> list[dict]:
    base_url = "https://api.zoom.us/v2/users/me/meetings"
    base_params = {
        "page_size": 300,
    }

    all_meetings = []
    next_page_token = None

    while True:
        params = dict(base_params)  # copy base params
        if next_page_token:
            params["next_page_token"] = next_page_token

        logger.info("zoom_meeting_sync_page_requested")
        response_data = _make_zoom_api_request(base_url, access_token, params)

        meetings = response_data.get("meetings", [])
        all_meetings.extend(meetings)

        next_page_token = response_data.get("next_page_token")
        if not next_page_token:
            break

    return all_meetings


def _upsert_zoom_meeting_to_zoom_oauth_connection_mapping(zoom_meeting_ids: list[int], zoom_oauth_connection: ZoomOAuthConnection):
    num_updated = 0
    num_created = 0

    with transaction.atomic():
        current = _locked_writable_zoom_oauth_connection(zoom_oauth_connection)
        zoom_oauth_app = current.zoom_oauth_app
        # Hold the connection row lock for all mapping writes. Removal therefore
        # linearizes either before this block (and rejects it) or after it.
        for zoom_meeting_id in zoom_meeting_ids:
            if not zoom_meeting_id:
                logger.warning("zoom_meeting_mapping_skipped code=missing_meeting_id")
                continue

            zoom_meeting_to_zoom_oauth_connection_mapping, created = ZoomMeetingToZoomOAuthConnectionMapping.objects.update_or_create(
                zoom_oauth_app=zoom_oauth_app,
                meeting_id=zoom_meeting_id,
                defaults={"zoom_oauth_connection": current},
            )
            if not created and zoom_meeting_to_zoom_oauth_connection_mapping.zoom_oauth_connection_id != current.id:
                zoom_meeting_to_zoom_oauth_connection_mapping.zoom_oauth_connection = current
                zoom_meeting_to_zoom_oauth_connection_mapping.save()
                num_updated += 1
            if created:
                num_created += 1

    logger.info(
        "zoom_meeting_mapping_upserted updated_count=%s created_count=%s",
        num_updated,
        num_created,
    )


def _handle_zoom_api_authentication_error(
    zoom_oauth_connection: ZoomOAuthConnection,
    _error: ZoomAPIAuthenticationError,
):
    try:
        with transaction.atomic():
            current = _locked_writable_zoom_oauth_connection(zoom_oauth_connection)
            if current.state == ZoomOAuthConnectionStates.DISCONNECTED:
                logger.info("zoom_oauth_auth_failure_ignored code=already_disconnected")
                return
            current.state = ZoomOAuthConnectionStates.DISCONNECTED
            current.connection_failure_data = {
                # This state is included in webhook payloads. Never retain an
                # exception string because provider libraries can embed bodies,
                # prepared requests, URLs, identifiers, or credentials in it.
                "error": "zoom_authentication_rejected",
                "timestamp": timezone.now().isoformat(),
            }
            current.save(update_fields=["state", "connection_failure_data", "updated_at"])
    except ZoomOAuthConnectionRemovalFenced:
        return
    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_oauth_auth_state_update_failed",
            "database_error",
            error,
        )
        raise ZoomAPIError("zoom_auth_state_update_failed") from None

    logger.error("zoom_oauth_connection_sync_failed code=authentication_error")

    # Preserve retry semantics while ensuring the Celery failure wrapper can
    # only render a fixed exception if webhook creation itself fails.
    try:
        trigger_webhook(
            webhook_trigger_type=WebhookTriggerTypes.ZOOM_OAUTH_CONNECTION_STATE_CHANGE,
            zoom_oauth_connection=current,
            payload=zoom_oauth_connection_webhook_payload(current),
        )
    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_oauth_auth_state_webhook_failed",
            "webhook_persistence_error",
            error,
        )
        raise ZoomAPIError("zoom_auth_state_webhook_failed") from None


def get_local_recording_token_via_zoom_oauth_app(bot: Bot) -> str | None:
    project = bot.project
    meeting_url = bot.meeting_url
    zoom_oauth_app = project.zoom_oauth_apps.first()
    if not zoom_oauth_app:
        return None

    meeting_id, password = parse_zoom_join_url(meeting_url)
    if not meeting_id:
        logger.info("zoom_local_recording_token_unavailable code=meeting_id_missing")
        return None

    mapping_for_meeting_id = ZoomMeetingToZoomOAuthConnectionMapping.objects.filter(zoom_oauth_app=zoom_oauth_app, meeting_id=str(meeting_id)).first()

    if not mapping_for_meeting_id:
        logger.info("zoom_local_recording_token_unavailable code=mapping_missing")
        return None

    zoom_oauth_connection = mapping_for_meeting_id.zoom_oauth_connection

    if not zoom_oauth_connection.is_local_recording_token_supported:
        logger.info("zoom_local_recording_token_unavailable code=capability_disabled")
        return None

    try:
        access_token = _get_access_token(zoom_oauth_connection)
        _assert_zoom_oauth_connection_writable(zoom_oauth_connection)
        local_recording_token = _get_local_recording_token(meeting_id, access_token)
        return local_recording_token

    except ZoomAPIAuthenticationError as error:
        _handle_zoom_api_authentication_error(zoom_oauth_connection, error)
        logger.error("zoom_local_recording_token_failed code=authentication_error")
        return None

    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_local_recording_token_failed",
            "provider_or_internal_error",
            error,
        )
        return None


class ZoomOnbehalfTokenUnavailableError(Exception):
    """
    SkyTerra: raised when a bot was created with zoom_settings.onbehalf_token but no
    onbehalf token could be obtained for that Zoom OAuth connection.

    Upstream degrades this case to a join WITHOUT the token, i.e. an anonymous join.
    A bot that asked to join on behalf of a user must never do that, so the token
    lookup fails closed and the bot controller ends the bot instead of joining.

    failure_reason is one of the ONBEHALF_TOKEN_FAILURE_* values below.
    """

    def __init__(self, failure_reason: str):
        self.failure_reason = failure_reason
        super().__init__(f"Onbehalf token unavailable: {failure_reason}")


# Machine-readable reasons why an onbehalf token could not be obtained.
ONBEHALF_TOKEN_FAILURE_NO_ZOOM_OAUTH_APP = "no_zoom_oauth_app"
ONBEHALF_TOKEN_FAILURE_CONNECTION_NOT_FOUND = "zoom_oauth_connection_not_found"
ONBEHALF_TOKEN_FAILURE_CONNECTION_DOES_NOT_SUPPORT_ONBEHALF_TOKENS = "zoom_oauth_connection_does_not_support_onbehalf_tokens"
ONBEHALF_TOKEN_FAILURE_NO_MEETING_ID = "no_meeting_id_in_meeting_url"
ONBEHALF_TOKEN_FAILURE_ZOOM_API_AUTHENTICATION_ERROR = "zoom_api_authentication_error"
ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR = "zoom_api_error"
ONBEHALF_TOKEN_FAILURE_ZOOM_API_RETURNED_NO_TOKEN = "zoom_api_returned_no_token"


def _get_onbehalf_token_and_failure_reason_via_zoom_oauth_app(bot: Bot) -> tuple[str | None, str | None]:
    """
    Returns (onbehalf_token, None) on success, (None, None) when the bot did not ask for an
    onbehalf token, and (None, failure_reason) when it asked for one and none could be obtained.
    """
    user_id_for_onbehalf_token = bot.zoom_onbehalf_token_zoom_oauth_connection_user_id()
    if not user_id_for_onbehalf_token:
        return None, None

    project = bot.project
    zoom_oauth_app = project.zoom_oauth_apps.first()
    if not zoom_oauth_app:
        return None, ONBEHALF_TOKEN_FAILURE_NO_ZOOM_OAUTH_APP

    zoom_oauth_connection = ZoomOAuthConnection.objects.filter(zoom_oauth_app=zoom_oauth_app, user_id=user_id_for_onbehalf_token).first()
    if not zoom_oauth_connection:
        return None, ONBEHALF_TOKEN_FAILURE_CONNECTION_NOT_FOUND

    if not zoom_oauth_connection.is_onbehalf_token_supported:
        logger.info("zoom_onbehalf_token_unavailable code=capability_disabled")
        return None, ONBEHALF_TOKEN_FAILURE_CONNECTION_DOES_NOT_SUPPORT_ONBEHALF_TOKENS

    meeting_url = bot.meeting_url

    meeting_id, password = parse_zoom_join_url(meeting_url)
    if not meeting_id:
        logger.info("zoom_onbehalf_token_unavailable code=meeting_id_missing")
        return None, ONBEHALF_TOKEN_FAILURE_NO_MEETING_ID

    try:
        access_token = _get_access_token(zoom_oauth_connection)
        _assert_zoom_oauth_connection_writable(zoom_oauth_connection)
        onbehalf_token = _get_onbehalf_token(meeting_id, access_token)
        if not onbehalf_token:
            return None, ONBEHALF_TOKEN_FAILURE_ZOOM_API_RETURNED_NO_TOKEN
        return onbehalf_token, None

    except ZoomAPIAuthenticationError as error:
        _handle_zoom_api_authentication_error(zoom_oauth_connection, error)
        logger.error("zoom_onbehalf_token_failed code=authentication_error")
        return None, ONBEHALF_TOKEN_FAILURE_ZOOM_API_AUTHENTICATION_ERROR

    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_onbehalf_token_failed",
            "provider_or_internal_error",
            error,
        )
        return None, ONBEHALF_TOKEN_FAILURE_ZOOM_API_ERROR


def get_onbehalf_token_via_zoom_oauth_app(bot: Bot) -> str | None:
    onbehalf_token, _ = _get_onbehalf_token_and_failure_reason_via_zoom_oauth_app(bot)
    return onbehalf_token


def get_zoom_tokens_via_zoom_oauth_app(bot: Bot) -> dict | None:
    """
    Raises ZoomOnbehalfTokenUnavailableError when the bot asked for an onbehalf token
    (zoom_settings.onbehalf_token) and none could be obtained. Bots that did not ask
    for one are unaffected.
    """
    onbehalf_token, onbehalf_token_failure_reason = _get_onbehalf_token_and_failure_reason_via_zoom_oauth_app(bot)
    if onbehalf_token_failure_reason:
        # Fail closed: never hand back a token set that would make an onbehalf bot join anonymously.
        raise ZoomOnbehalfTokenUnavailableError(onbehalf_token_failure_reason)

    local_recording_token = get_local_recording_token_via_zoom_oauth_app(bot)

    return {
        "zak_token": None,
        "join_token": None,
        "app_privilege_token": local_recording_token,
        "onbehalf_token": onbehalf_token,
    }
