import logging

from django.db import transaction
from django.utils import timezone

from attendee.logging import log_bounded_exception
from bots.models import ZoomOAuthConnection, ZoomOAuthConnectionStates
from bots.zoom_oauth_connections_utils import (
    ZoomAPIAuthenticationError,
    ZoomAPIError,
    ZoomOAuthConnectionRemovalFenced,
    _assert_zoom_oauth_connection_writable,
    _get_access_token,
    _get_zoom_meetings,
    _get_zoom_personal_meeting_id,
    _handle_zoom_api_authentication_error,
    _upsert_zoom_meeting_to_zoom_oauth_connection_mapping,
    update_zoom_oauth_connection_if_writable,
)

logger = logging.getLogger(__name__)

from celery import shared_task


def enqueue_sync_zoom_oauth_connection_task(zoom_oauth_connection: ZoomOAuthConnection):
    """Enqueue a sync zoom oauth connection task for a zoom oauth connection."""
    if not zoom_oauth_connection.is_local_recording_token_supported:
        logger.info("zoom_oauth_sync_skipped code=capability_disabled")
        return

    # Write only the scheduling fields on the locked live row: a stale
    # scheduler instance must never re-save (or re-insert) purged credentials.
    with transaction.atomic():
        try:
            current = update_zoom_oauth_connection_if_writable(
                zoom_oauth_connection, sync_task_enqueued_at=timezone.now(), sync_task_requested_at=None,
            )
        except ZoomOAuthConnectionRemovalFenced:
            logger.info("zoom_oauth_sync_skipped code=removal_fenced")
            return
        zoom_oauth_connection.sync_task_enqueued_at = current.sync_task_enqueued_at
        zoom_oauth_connection.sync_task_requested_at = None
        sync_zoom_oauth_connection.delay(zoom_oauth_connection.id)


@shared_task(
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,  # Enable exponential backoff
    max_retries=6,
)
def sync_zoom_oauth_connection(self, zoom_oauth_connection_id):
    """Celery task to sync zoom meetings with a zoom oauth connection."""
    logger.info("zoom_oauth_sync_started")
    zoom_oauth_connection = None

    try:
        zoom_oauth_connection = ZoomOAuthConnection.objects.get(id=zoom_oauth_connection_id)
        # Set the sync start time
        sync_started_at = timezone.now()

        access_token = _get_access_token(zoom_oauth_connection)
        _assert_zoom_oauth_connection_writable(zoom_oauth_connection)
        zoom_meetings = _get_zoom_meetings(access_token)

        logger.info("zoom_oauth_sync_provider_result meeting_count=%s", len(zoom_meetings))

        _assert_zoom_oauth_connection_writable(zoom_oauth_connection)
        zoom_personal_meeting_id = _get_zoom_personal_meeting_id(access_token)
        zoom_meeting_ids = [zoom_meeting["id"] for zoom_meeting in zoom_meetings] + [zoom_personal_meeting_id]

        _upsert_zoom_meeting_to_zoom_oauth_connection_mapping(zoom_meeting_ids, zoom_oauth_connection)

        # Update zoom oauth connection sync success timestamp and window
        completed_at = timezone.now()
        update_zoom_oauth_connection_if_writable(
            zoom_oauth_connection,
            last_attempted_sync_at=completed_at,
            last_successful_sync_at=completed_at,
            last_successful_sync_started_at=sync_started_at,
            state=ZoomOAuthConnectionStates.CONNECTED,
            connection_failure_data=None,
        )

    except ZoomOAuthConnectionRemovalFenced:
        return

    except ZoomAPIAuthenticationError as e:
        _handle_zoom_api_authentication_error(zoom_oauth_connection, e)

    except ZoomOAuthConnection.DoesNotExist:
        logger.error("zoom_oauth_sync_failed code=connection_not_found")
        return

    except Exception as error:
        log_bounded_exception(
            logger,
            "zoom_oauth_sync_failed",
            "provider_or_internal_error",
            error,
        )
        if zoom_oauth_connection is not None:
            try:
                update_zoom_oauth_connection_if_writable(
                    zoom_oauth_connection,
                    last_attempted_sync_at=timezone.now(),
                )
            except ZoomOAuthConnectionRemovalFenced:
                return
            except Exception as status_error:
                log_bounded_exception(
                    logger,
                    "zoom_oauth_sync_failed",
                    "status_write_failed",
                    status_error,
                )
        raise ZoomAPIError("zoom_oauth_sync_failed") from None
