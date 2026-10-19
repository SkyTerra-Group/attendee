import logging

from attendee.logging import log_bounded_exception
from bots.models import ZoomOAuthConnection, ZoomOAuthConnectionStates
from bots.zoom_oauth_connections_utils import (
    ZoomAPIError,
    ZoomOAuthConnectionRemovalFenced,
    _get_access_token,
    update_zoom_oauth_connection_if_writable,
)

logger = logging.getLogger(__name__)

from celery import shared_task

from bots.models import WebhookTriggerTypes, ZoomOAuthApp
from bots.webhook_utils import trigger_webhook
from bots.zoom_oauth_connections_utils import zoom_oauth_connection_webhook_payload


@shared_task(
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,  # Enable exponential backoff
    max_retries=1,
)
def validate_zoom_oauth_connections(self, zoom_oauth_app_id):
    """Celery task to sync zoom meetings with a zoom oauth connection."""
    logger.info("zoom_oauth_validation_started")
    try:
        zoom_oauth_app = ZoomOAuthApp.objects.get(id=zoom_oauth_app_id)
        disconnected_zoom_oauth_connections = ZoomOAuthConnection.objects.filter(
            zoom_oauth_app=zoom_oauth_app,
            state=ZoomOAuthConnectionStates.DISCONNECTED,
        )
        for zoom_oauth_connection in disconnected_zoom_oauth_connections:
            connection_failure_error = (
                zoom_oauth_connection.connection_failure_data or {}
            ).get("error")
            if not connection_failure_error:
                continue
            # Rows written before the bounded-state migration may retain the
            # provider's legacy invalid-client phrase. Inspect it only for
            # compatibility; never emit or copy that arbitrary text.
            if connection_failure_error not in {
                "zoom_authentication_rejected",
                "Invalid client_id or client_secret",
            } and not (
                isinstance(connection_failure_error, str)
                and "Invalid client_id or client_secret" in connection_failure_error
            ):
                continue

            try:
                access_token = _get_access_token(zoom_oauth_connection)
                if not access_token:
                    continue

                current = update_zoom_oauth_connection_if_writable(
                    zoom_oauth_connection,
                    state=ZoomOAuthConnectionStates.CONNECTED,
                    connection_failure_data=None,
                )
                trigger_webhook(
                    webhook_trigger_type=WebhookTriggerTypes.ZOOM_OAUTH_CONNECTION_STATE_CHANGE,
                    zoom_oauth_connection=current,
                    payload=zoom_oauth_connection_webhook_payload(current),
                )
            except ZoomOAuthConnectionRemovalFenced:
                continue
            except Exception as error:
                log_bounded_exception(
                    logger,
                    "zoom_oauth_validation_failed",
                    "provider_or_internal_error",
                    error,
                )
                continue
    except ZoomOAuthApp.DoesNotExist:
        logger.error("zoom_oauth_validation_failed code=app_not_found")
        return
    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_oauth_validation_failed",
            "task_or_database_error",
            error,
        )
        raise ZoomAPIError("zoom_oauth_validation_failed") from None
