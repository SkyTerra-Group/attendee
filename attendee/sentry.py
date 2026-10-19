import logging


logger = logging.getLogger(__name__)


def init_sentry():
    """Keep external SDK telemetry disabled for this Zoom-capable service.

    Disabling request bodies and traceback locals does not remove exception
    values, breadcrumbs or other envelope fields. Generic Django/Celery/bot
    work cannot reliably be classified as non-Zoom at this boundary. Until a
    whole-envelope policy is reviewed, even a configured DSN must not install
    the SDK integrations. There is deliberately no environment bypass.

    This does not sanitize historical Sentry events or an SDK initialized by
    external instrumentation. Deployment must use the repository entrypoints
    without an injected Sentry initializer. Ordinary console logging remains.
    """
    logger.warning(
        "sentry_telemetry_disabled code=zoom_sensitive_service "
        "console_diagnostics=enabled"
    )
