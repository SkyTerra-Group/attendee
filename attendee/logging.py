import logging
import re
from datetime import datetime, timezone

from pythonjsonlogger import jsonlogger

_ALLOWED_EXCEPTION_CLASSES = {
    "CallbackError",
    "CallbackHTTPError",
    "CallbackTimeoutError",
    "ConnectTimeout",
    "ConnectionError",
    "HTTPError",
    "IntegrityError",
    "JSONDecodeError",
    "ReadTimeout",
    "Timeout",
    "TimeoutError",
    "ValueError",
    "ZoomAPIAuthenticationError",
    "ZoomAPIError",
    "ZoomOAuthConnectionRemovalFenced",
}


def bounded_http_status_class(status_code) -> str:
    """Reduce an HTTP status to its non-content-bearing class."""

    return (
        f"{status_code // 100}xx"
        if type(status_code) is int and 100 <= status_code <= 599
        else "none"
    )


def bounded_exception_metadata(error: BaseException) -> tuple[str, str]:
    """Return allowlisted exception metadata without rendering ``error``.

    Zoom/provider exceptions frequently retain a response, prepared request,
    body, URL, or token in ``str(error)`` and ``repr(error)``.  Trust-boundary
    logging uses this single mapper and never serializes those objects.
    """

    exception_class = type(error).__name__
    if exception_class not in _ALLOWED_EXCEPTION_CLASSES:
        exception_class = "other"

    response = getattr(error, "response", None)
    status_code = getattr(response, "status_code", None)
    status_class = bounded_http_status_class(status_code)
    return exception_class, status_class


def log_bounded_exception(logger, event: str, code: str, error: BaseException) -> None:
    """Emit one fixed Zoom-boundary event with bounded exception metadata."""

    exception_class, status_class = bounded_exception_metadata(error)
    logger.error(
        "%s code=%s exception_class=%s http_status_class=%s",
        event,
        code,
        exception_class,
        status_class,
    )


class ZoomTrustBoundaryRedactionFilter(logging.Filter):
    """Last-line redaction for request/access logs around the Zoom trust path.

    Call sites still emit bounded codes.  This filter covers framework request
    messages whose path is formatted after the view returns, outside those
    call sites.  It intentionally does not try to preserve query values.
    """

    _OBJECT_ID = re.compile(r"\b(?:zoa|zoc|bot|proj)_[A-Za-z0-9_-]{4,}\b")
    _QUERY = re.compile(r"(?P<path>/[^\s?]*)\?[^\s]*")
    _COMPACT_JWS = re.compile(
        r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
    )
    _ZOOM_LOGGER_PREFIXES = (
        "bots.external_callback_utils",
        "bots.external_webhooks_views",
        "bots.tasks.deliver_webhook_task",
        "bots.tasks.refresh_zoom_oauth_connection_task",
        "bots.tasks.sync_zoom_oauth_connection_task",
        "bots.tasks.validate_zoom_oauth_connections_task",
        "bots.zoom_",
    )
    _ZOOM_PATH_MARKERS = (
        "/zoom",
        "/external_webhooks/zoom/",
    )
    _SAFE_EXTRA_FIELDS = {
        "status_code",
        "request_time",
        "server_time",
    }
    _STANDARD_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)

    @classmethod
    def _is_zoom_boundary(cls, record, message: str) -> bool:
        if record.name.startswith(cls._ZOOM_LOGGER_PREFIXES):
            return True
        lowered = message.lower()
        if "zoom" in lowered:
            return True
        request = getattr(record, "request", None)
        path = getattr(request, "path", "")
        return isinstance(path, str) and any(marker in path for marker in cls._ZOOM_PATH_MARKERS)

    def filter(self, record):
        try:
            message = record.getMessage()
        except Exception:
            message = "log_message_redacted"
        message = self._OBJECT_ID.sub("[redacted-id]", message)
        message = self._QUERY.sub(r"\g<path>?[redacted-query]", message)
        message = self._COMPACT_JWS.sub("[redacted-assertion]", message)
        is_zoom_boundary = self._is_zoom_boundary(record, message)
        record.msg = message
        record.args = ()
        if is_zoom_boundary:
            # JSON formatters include arbitrary LogRecord extras.  Framework
            # request objects stringify to a path and query, and exception
            # objects may carry provider bodies, prepared requests, or tokens.
            # Zoom-boundary call sites put all approved metadata in ``message``;
            # retain only bounded access timing/status extras here.
            for key in tuple(vars(record)):
                if key in self._STANDARD_RECORD_FIELDS or key in self._SAFE_EXTRA_FIELDS:
                    continue
                setattr(record, key, "[redacted]")
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True


class ISOJsonFormatter(jsonlogger.JsonFormatter):
    """
    JSON formatter that adds ISO 8601 timestamp
    """

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)

        # Add ISO timestamp from the record's created time
        # record.created is a Unix timestamp (float)
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        log_record["timestamp"] = dt.isoformat()
