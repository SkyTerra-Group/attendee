import hmac
import json
import re

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction

from bots.models import Project, ZoomOAuthApp, ZoomRemovalAuditKeyFingerprint
from bots.zoom_deauthorization_readiness import DeauthorizationReadinessError, collect_readiness
from bots.zoom_removal_audit import (
    AUDIT_KEY_ALGORITHM,
    AUDIT_KEY_DERIVATION_DOMAIN,
    AUDIT_KEY_DERIVATION_VERSION,
    AuditKeyringError,
    configured_audit_keyrings,
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class Command(BaseCommand):
    help = "Explicitly register immutable non-secret fingerprints for configured Zoom audit keys"

    def add_arguments(self, parser):
        parser.add_argument("--expected-registry-fingerprint", required=True)
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        if settings.ENABLE_ZOOM_RETENTION_REMOVAL_API or settings.ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE:
            raise CommandError("feature_flags_must_be_off")
        expected = options["expected_registry_fingerprint"]
        if type(expected) is not str or not _HEX64_RE.fullmatch(expected):
            raise CommandError("registry_fingerprint_invalid")
        try:
            registry = configured_audit_keyrings()
            collect_readiness(
                require_registered_keys=False,
                require_legacy_recovery=False,
            )
        except (AuditKeyringError, DeauthorizationReadinessError) as error:
            raise CommandError(getattr(error, "code", "audit_key_unavailable")) from None
        if not hmac.compare_digest(expected, registry.fingerprint):
            raise CommandError("registry_fingerprint_mismatch")

        created = 0
        existing = 0
        try:
            with transaction.atomic():
                for ring in registry.rings:
                    project = Project.objects.select_for_update().get(object_id=ring.project_object_id)
                    app = ZoomOAuthApp.objects.select_for_update().get(
                        project=project,
                        deauthorization_binding_id=ring.app_binding,
                    )
                    for kid, fingerprint in ring.key_fingerprints.items():
                        registered = ZoomRemovalAuditKeyFingerprint.objects.filter(
                            project=project,
                            zoom_oauth_app=app,
                            key_id=kid,
                        ).first()
                        if registered is not None:
                            if (
                                registered.key_fingerprint != fingerprint
                                or registered.algorithm != AUDIT_KEY_ALGORITHM
                                or registered.derivation_domain != AUDIT_KEY_DERIVATION_DOMAIN
                                or registered.derivation_version != AUDIT_KEY_DERIVATION_VERSION
                            ):
                                raise CommandError("audit_key_conflict")
                            existing += 1
                            continue
                        if ZoomRemovalAuditKeyFingerprint.objects.filter(
                            key_fingerprint=fingerprint
                        ).exists():
                            raise CommandError("audit_key_conflict")
                        if options["apply"]:
                            ZoomRemovalAuditKeyFingerprint.objects.create(
                                project=project,
                                zoom_oauth_app=app,
                                key_id=kid,
                                key_fingerprint=fingerprint,
                                algorithm=AUDIT_KEY_ALGORITHM,
                                derivation_domain=AUDIT_KEY_DERIVATION_DOMAIN,
                                derivation_version=AUDIT_KEY_DERIVATION_VERSION,
                            )
                        created += 1
                if not options["apply"]:
                    transaction.set_rollback(True)
        except (IntegrityError, Project.DoesNotExist, ZoomOAuthApp.DoesNotExist):
            raise CommandError("audit_key_registration_conflict") from None

        self.stdout.write(
            json.dumps(
                {
                    "applied": bool(options["apply"]),
                    "audit_registry_fingerprint": registry.fingerprint,
                    "configured_ring_count": len(registry.rings),
                    "registered_key_count": created,
                    "existing_key_count": existing,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
