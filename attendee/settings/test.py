import os

from .base import *
from .base import LOG_FILTERS

DEBUG = True
SITE_DOMAIN = "localhost:8000"
ALLOWED_HOSTS = []

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "attendee_test",
        "USER": "attendee_test_user",
        "PASSWORD": "attendee_test_user",
        "HOST": os.getenv("POSTGRES_HOST", "localhost"),
        "PORT": "5432",
    }
}


# Log more stuff in development
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": LOG_FILTERS,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "filters": ["zoom_trust_boundary_redaction"],
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
