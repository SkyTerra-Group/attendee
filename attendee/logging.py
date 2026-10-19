import logging
import re
from datetime import datetime, timezone

from pythonjsonlogger import jsonlogger


class ZoomTrustBoundaryRedactionFilter(logging.Filter):
    """Last-line redaction for request/access logs around the Zoom trust path.

    Call sites still emit bounded codes.  This filter covers framework request
    messages whose path is formatted after the view returns, outside those
    call sites.  It intentionally does not try to preserve query values.
    """

    _OBJECT_ID = re.compile(r"\b(?:zoa|zoc|bot|proj)_[A-Za-z0-9_-]{4,}\b")
    _QUERY = re.compile(r"(?P<path>/[^\s?]*)\?[^\s]*")

    def filter(self, record):
        try:
            message = record.getMessage()
        except Exception:
            message = "log_message_redacted"
        message = self._OBJECT_ID.sub("[redacted-id]", message)
        message = self._QUERY.sub(r"\g<path>?[redacted-query]", message)
        record.msg = message
        record.args = ()
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
