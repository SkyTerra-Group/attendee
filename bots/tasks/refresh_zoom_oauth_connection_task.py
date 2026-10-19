import logging

from django.db import transaction
from django.utils import timezone

from attendee.logging import log_bounded_exception
from bots.models import ZoomOAuthConnection, ZoomOAuthConnectionStates
from bots.zoom_oauth_connections_utils import (
    ZoomAPIAuthenticationError,
    ZoomAPIError,
    ZoomOAuthConnectionRemovalFenced,
    _get_access_token,
    _handle_zoom_api_authentication_error,
    update_zoom_oauth_connection_if_writable,
)

logger = logging.getLogger(__name__)

from celery import shared_task


def enqueue_refresh_zoom_oauth_connection_task(zoom_oauth_connection: ZoomOAuthConnection):
    """Enqueue a refresh zoom oauth connection task for a zoom oauth connection."""

    with transaction.atomic():
        zoom_oauth_connection.token_refresh_task_enqueued_at = timezone.now()
        zoom_oauth_connection.token_refresh_task_requested_at = None
        zoom_oauth_connection.save()
        refresh_zoom_oauth_connection.delay(zoom_oauth_connection.id)


@shared_task(
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,  # Enable exponential backoff
    max_retries=6,
)
def refresh_zoom_oauth_connection(self, zoom_oauth_connection_id):
    """Celery task to refresh the token for a zoom oauth connection."""
    logger.info("zoom_oauth_refresh_started")
    zoom_oauth_connection = None

    try:
        zoom_oauth_connection = ZoomOAuthConnection.objects.get(id=zoom_oauth_connection_id)
        # Just get the access token which will refresh the refresh token
        access_token = _get_access_token(zoom_oauth_connection)

        if not access_token:
            raise ZoomAPIError("zoom_refresh_access_token_missing")

        # Update zoom oauth connection sync success timestamp and window
        completed_at = timezone.now()
        update_zoom_oauth_connection_if_writable(
            zoom_oauth_connection,
            last_attempted_token_refresh_at=completed_at,
            last_successful_token_refresh_at=completed_at,
            state=ZoomOAuthConnectionStates.CONNECTED,
            connection_failure_data=None,
        )

        logger.info("zoom_oauth_refresh_completed")

    except ZoomOAuthConnectionRemovalFenced:
        return

    except ZoomAPIAuthenticationError as e:
        _handle_zoom_api_authentication_error(zoom_oauth_connection, e)

    except ZoomOAuthConnection.DoesNotExist:
        logger.error("zoom_oauth_refresh_failed code=connection_not_found")
        return

    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_oauth_refresh_failed",
            "provider_or_internal_error",
            error,
        )
        if zoom_oauth_connection is not None:
            try:
                update_zoom_oauth_connection_if_writable(
                    zoom_oauth_connection,
                    last_attempted_token_refresh_at=timezone.now(),
                )
            except ZoomOAuthConnectionRemovalFenced:
                return
            except Exception as status_error:
                log_bounded_exception(
                    logger,
                    "zoom_oauth_refresh_failed",
                    "status_write_failed",
                    status_error,
                )
        # Celery renders an unhandled task exception. Replace any provider or
        # library exception with a fixed code before it reaches that wrapper.
        raise ZoomAPIError("zoom_oauth_refresh_failed") from None
