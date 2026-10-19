import io
import logging

from attendee.logging import ISOJsonFormatter, ZoomTrustBoundaryRedactionFilter


class _RawByteHandler(logging.Handler):
    """Render exactly what a configured handler would emit, then retain bytes."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.output = bytearray()
        self.addFilter(ZoomTrustBoundaryRedactionFilter())
        self.setFormatter(
            ISOJsonFormatter("%(timestamp)s %(name)s %(levelname)s %(message)s")
        )

    def emit(self, record):
        self.output.extend(self.format(record).encode("utf-8", errors="strict"))
        self.output.extend(b"\n")


class CaptureZoomLogBytes:
    """Capture post-filter application, worker, web, and Django access bytes."""

    def __init__(self):
        self.handler = _RawByteHandler()
        # Django's configured logger does not propagate. Other app and Celery
        # loggers reach root, so these two attachment points cover all planes.
        self.loggers = [logging.getLogger(), logging.getLogger("django")]
        self._levels = []

    def __enter__(self):
        for logger in self.loggers:
            self._levels.append(logger.level)
            logger.setLevel(logging.DEBUG)
            logger.addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for logger, level in zip(self.loggers, self._levels, strict=True):
            logger.removeHandler(self.handler)
            logger.setLevel(level)

    @property
    def bytes(self) -> bytes:
        return bytes(self.handler.output)

    @property
    def text(self) -> str:
        return self.bytes.decode("utf-8")

    def assert_absent(self, test_case, *markers) -> None:
        for marker in markers:
            if marker is None:
                continue
            encoded = marker if isinstance(marker, bytes) else str(marker).encode("utf-8")
            test_case.assertNotIn(encoded, self.bytes)


class CaptureConfiguredZoomLogBytes:
    """Capture bytes emitted by Django's already-configured handlers.

    Unlike ``CaptureZoomLogBytes``, this does not install a test handler or a
    test filter. It redirects the streams of the handlers built from the active
    Django ``LOGGING`` setting, so route, Gunicorn-style access, and Celery
    trace records exercise the same production filter chain.
    """

    def __init__(self):
        self._handler_state = []
        self._logger_state = []
        self._buffers = []

    def __enter__(self):
        handlers = []
        seen = set()
        for logger in (logging.getLogger(), logging.getLogger("django")):
            self._logger_state.append((logger, logger.level))
            logger.setLevel(logging.DEBUG)
            for handler in logger.handlers:
                if id(handler) in seen or not isinstance(handler, logging.StreamHandler):
                    continue
                seen.add(id(handler))
                handlers.append(handler)

        if not handlers:
            raise AssertionError("configured_stream_handler_missing")

        for handler in handlers:
            if not any(
                isinstance(filter_, ZoomTrustBoundaryRedactionFilter)
                for filter_ in handler.filters
            ):
                raise AssertionError("configured_zoom_redaction_filter_missing")
            buffer = io.StringIO()
            self._handler_state.append((handler, handler.stream))
            self._buffers.append(buffer)
            handler.stream = buffer
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for handler, stream in self._handler_state:
            handler.flush()
            handler.stream = stream
        for logger, level in self._logger_state:
            logger.setLevel(level)

    @property
    def bytes(self) -> bytes:
        return "".join(buffer.getvalue() for buffer in self._buffers).encode(
            "utf-8",
            errors="strict",
        )

    @property
    def text(self) -> str:
        return self.bytes.decode("utf-8")

    def assert_absent(self, test_case, *markers) -> None:
        for marker in markers:
            if marker is None:
                continue
            encoded = marker if isinstance(marker, bytes) else str(marker).encode("utf-8")
            test_case.assertNotIn(encoded, self.bytes)
