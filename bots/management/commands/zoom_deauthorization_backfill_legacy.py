import hmac
import json
import re
import uuid

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction

from bots.models import (
    Project,
    ZoomOAuthApp,
    ZoomOAuthAuthorizationGrant,
    ZoomOAuthAuthorizationLineage,
    ZoomOAuthConnection,
)
from bots.zoom_deauthorization_grants import (
    GrantCaptureUnavailable,
    configured_clock_evidence,
    connection_binding_candidates,
    database_clock_now,
    provider_identity_candidates,
    valid_provider_identity_component,
)
from bots.zoom_deauthorization_readiness import DeauthorizationReadinessError, collect_readiness
from bots.zoom_removal_audit import AuditKeyringError, configured_audit_keyring, configured_audit_keyrings

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class Command(BaseCommand):
    help = "Fingerprint-verified pre-enable recovery of legacy Zoom identity history"

    def add_arguments(self, parser):
        parser.add_argument("--expected-registry-fingerprint", required=True)
        parser.add_argument("--apply", action="store_true")
        parser.add_argument("--establish-clean-baseline", action="append", default=[], metavar="APP_BINDING_UUID")

    def handle(self, *args, **options):
        if settings.ENABLE_ZOOM_RETENTION_REMOVAL_API or settings.ENABLE_ZOOM_DEAUTHORIZATION_GRANT_CAPTURE:
            raise CommandError("feature_flags_must_be_off")
        expected = options["expected_registry_fingerprint"]
        if type(expected) is not str or not _HEX64_RE.fullmatch(expected):
            raise CommandError("registry_fingerprint_invalid")
        try:
            registry = configured_audit_keyrings()
            readiness = collect_readiness(require_legacy_recovery=False)
        except (AuditKeyringError, DeauthorizationReadinessError) as error:
            raise CommandError(getattr(error, "code", "audit_key_unavailable")) from None
        if not hmac.compare_digest(expected, registry.fingerprint):
            raise CommandError("registry_fingerprint_mismatch")

        supplied_baselines = options["establish_clean_baseline"]
        try:
            baseline_bindings = [uuid.UUID(value) for value in supplied_baselines]
        except (ValueError, TypeError):
            raise CommandError("app_binding_invalid") from None
        if any(
            str(parsed) != supplied
            for parsed, supplied in zip(baseline_bindings, supplied_baselines, strict=True)
        ):
            raise CommandError("app_binding_invalid")

        summary = {
            "applied": bool(options["apply"]),
            "audit_registry_fingerprint": readiness.audit_registry_fingerprint,
            "configured_ring_count": len(registry.rings),
            "legacy_successors_created": 0,
            "legacy_successors_existing": 0,
            "legacy_grants_unrecoverable": 0,
            "legacy_grants_sealed": 0,
            "orphan_connections_quarantined": 0,
            "app_recovery_markers_written": 0,
            "clean_baselines_established": 0,
            "legacy_barrier_retained": True,
        }

        try:
            with transaction.atomic():
                scoped_apps = []
                for configured_ring in registry.rings:
                    project = Project.objects.select_for_update().get(
                        object_id=configured_ring.project_object_id
                    )
                    app = ZoomOAuthApp.objects.select_for_update().get(
                        project=project,
                        deauthorization_binding_id=configured_ring.app_binding,
                    )
                    scoped_apps.append(app)
                app_by_binding = {app.deauthorization_binding_id: app for app in scoped_apps}
                if any(binding not in app_by_binding for binding in baseline_bindings):
                    raise CommandError("app_binding_not_found")

                clock = configured_clock_evidence()
                for app in scoped_apps:
                    ring = configured_audit_keyring(app.project, app)
                    legacy_grants = list(
                        ZoomOAuthAuthorizationGrant.objects.select_for_update(of=("self",))
                        .select_related("project", "zoom_oauth_app", "lineage", "live_connection")
                        .filter(zoom_oauth_app=app, identity_audit_key_id__isnull=True, legacy_history=True)
                        .order_by("pk")
                    )
                    for legacy_grant in legacy_grants:
                        if legacy_grant.legacy_recovery_outcome is not None:
                            if (
                                legacy_grant.live_connection_id is not None
                                or legacy_grant.generation_ended_at is None
                                or legacy_grant.legacy_recovery_outcome
                                not in {"successor_linked", "unrecoverable"}
                            ):
                                raise CommandError("legacy_backfill_conflict")
                            if legacy_grant.legacy_recovery_outcome == "successor_linked":
                                if not ZoomOAuthAuthorizationLineage.objects.filter(
                                    legacy_predecessor=legacy_grant.lineage
                                ).exists():
                                    raise CommandError("legacy_backfill_conflict")
                                summary["legacy_successors_existing"] += 1
                            else:
                                summary["legacy_grants_unrecoverable"] += 1
                            continue
                        connection = legacy_grant.live_connection
                        outcome = "unrecoverable"
                        if connection is not None:
                            if not valid_provider_identity_component(
                                connection.user_id
                            ) or not valid_provider_identity_component(connection.account_id):
                                raise CommandError("legacy_identity_unavailable")
                            identity_candidates = provider_identity_candidates(
                                legacy_grant.project,
                                app,
                                connection.user_id,
                                connection.account_id,
                            )
                            connection_ring, _connection_candidates = connection_binding_candidates(connection)
                            if connection_ring.fingerprint != ring.fingerprint:
                                raise CommandError("audit_key_conflict")
                            candidate_map = dict(identity_candidates)
                            current_digest = candidate_map[ring.current_kid]
                            if hmac.compare_digest(
                                current_digest,
                                legacy_grant.lineage.identity_digest,
                            ):
                                # The permanent 0094 tombstone cannot be
                                # relabeled in place or duplicated under its
                                # uniqueness constraint. Rotate to fresh
                                # current material while retaining this key,
                                # then rerun recovery.
                                raise CommandError("legacy_backfill_requires_current_key_rotation")
                            existing = ZoomOAuthAuthorizationLineage.objects.select_for_update().filter(
                                project=legacy_grant.project,
                                zoom_oauth_app=app,
                                identity_digest__in=candidate_map.values(),
                                identity_audit_key_id__isnull=False,
                            )
                            matches = list(existing)
                            if len(matches) > 1:
                                raise CommandError("audit_key_conflict")
                            if matches:
                                successor = matches[0]
                                if successor.legacy_predecessor_id != legacy_grant.lineage_id:
                                    raise CommandError("audit_key_conflict")
                                summary["legacy_successors_existing"] += 1
                            else:
                                if options["apply"]:
                                    ZoomOAuthAuthorizationLineage.objects.create(
                                        project=legacy_grant.project,
                                        zoom_oauth_app=app,
                                        identity_digest=current_digest,
                                        identity_audit_key_id=ring.current_kid,
                                        identity_audit_key_fingerprint=ring.key_fingerprints[
                                            ring.current_kid
                                        ],
                                        legacy_predecessor=legacy_grant.lineage,
                                        latest_grant_sequence=max(
                                            legacy_grant.lineage.latest_grant_sequence,
                                            legacy_grant.grant_sequence,
                                        ),
                                        has_prior_grant=True,
                                        history_complete=False,
                                    )
                                summary["legacy_successors_created"] += 1
                            outcome = "successor_linked"

                        if options["apply"]:
                            if legacy_grant.generation_ended_at is None:
                                boundary = database_clock_now()
                                if boundary <= legacy_grant.generation_started_at:
                                    raise CommandError("grant_boundary_invalid")
                                legacy_grant.generation_ended_at = boundary
                                legacy_grant.end_clock_health_id = clock.health_id
                                legacy_grant.end_clock_error_ms = clock.error_ms
                                legacy_grant.end_clock_continuous = clock.continuous
                            legacy_grant.live_connection = None
                            legacy_grant.legacy_recovery_outcome = outcome
                            legacy_grant.save(
                                update_fields=[
                                    "generation_ended_at",
                                    "end_clock_health_id",
                                    "end_clock_error_ms",
                                    "end_clock_continuous",
                                    "live_connection",
                                    "legacy_recovery_outcome",
                                    "updated_at",
                                ]
                            )
                        if outcome == "unrecoverable":
                            summary["legacy_grants_unrecoverable"] += 1
                        summary["legacy_grants_sealed"] += 1

                    orphan_connections = list(
                        ZoomOAuthConnection.objects.select_for_update(of=("self",))
                        .filter(zoom_oauth_app=app, authorization_grant__isnull=True)
                        .order_by("pk")
                    )
                    for orphan in orphan_connections:
                        if not valid_provider_identity_component(
                            orphan.user_id
                        ) or not valid_provider_identity_component(orphan.account_id):
                            raise CommandError("legacy_identity_unavailable")
                        identity_candidates = provider_identity_candidates(
                            app.project,
                            app,
                            orphan.user_id,
                            orphan.account_id,
                        )
                        identity_by_digest = {digest: kid for kid, digest in identity_candidates}
                        unkeyed_matches = list(
                            ZoomOAuthAuthorizationLineage.objects.select_for_update().filter(
                                project=app.project,
                                zoom_oauth_app=app,
                                identity_digest__in=identity_by_digest,
                                identity_audit_key_id__isnull=True,
                            )
                        )
                        if len(unkeyed_matches) > 1:
                            raise CommandError("audit_key_conflict")
                        current_identity_digest = dict(identity_candidates)[ring.current_kid]
                        if unkeyed_matches and hmac.compare_digest(
                            unkeyed_matches[0].identity_digest,
                            current_identity_digest,
                        ):
                            raise CommandError("legacy_backfill_requires_current_key_rotation")
                        matches = list(
                            ZoomOAuthAuthorizationLineage.objects.select_for_update().filter(
                                project=app.project,
                                zoom_oauth_app=app,
                                identity_digest__in=identity_by_digest,
                                identity_audit_key_id__isnull=False,
                            )
                        )
                        if len(matches) > 1:
                            raise CommandError("audit_key_conflict")
                        if matches:
                            lineage = matches[0]
                            expected_kid = identity_by_digest[lineage.identity_digest]
                            if (
                                lineage.identity_audit_key_id != expected_kid
                                or lineage.identity_audit_key_fingerprint
                                != ring.key_fingerprints[expected_kid]
                                or lineage.history_complete
                                or not lineage.has_prior_grant
                                or lineage.grants.filter(generation_ended_at__isnull=True).exists()
                            ):
                                raise CommandError("legacy_backfill_conflict")
                        else:
                            lineage = None
                            if options["apply"]:
                                lineage = ZoomOAuthAuthorizationLineage.objects.create(
                                    project=app.project,
                                    zoom_oauth_app=app,
                                    identity_digest=current_identity_digest,
                                    identity_audit_key_id=ring.current_kid,
                                    identity_audit_key_fingerprint=ring.key_fingerprints[
                                        ring.current_kid
                                    ],
                                    legacy_predecessor=(
                                        unkeyed_matches[0] if unkeyed_matches else None
                                    ),
                                    latest_grant_sequence=(
                                        unkeyed_matches[0].latest_grant_sequence
                                        if unkeyed_matches
                                        else 0
                                    ),
                                    has_prior_grant=True,
                                    history_complete=False,
                                )
                        if options["apply"]:
                            next_sequence = lineage.latest_grant_sequence + 1
                            lineage.latest_grant_sequence = next_sequence
                            lineage.has_prior_grant = True
                            lineage.save(
                                update_fields=["latest_grant_sequence", "has_prior_grant", "updated_at"]
                            )
                            connection_ring, connection_candidates = connection_binding_candidates(orphan)
                            if connection_ring.fingerprint != ring.fingerprint:
                                raise CommandError("audit_key_conflict")
                            ZoomOAuthAuthorizationGrant.objects.create(
                                project=app.project,
                                zoom_oauth_app=app,
                                lineage=lineage,
                                grant_sequence=next_sequence,
                                live_connection=orphan,
                                connection_digest=dict(connection_candidates)[ring.current_kid],
                                connection_audit_key_id=ring.current_kid,
                                connection_audit_key_fingerprint=ring.key_fingerprints[
                                    ring.current_kid
                                ],
                                identity_digest=lineage.identity_digest,
                                identity_audit_key_id=lineage.identity_audit_key_id,
                                identity_audit_key_fingerprint=lineage.identity_audit_key_fingerprint,
                                authorization_generation=orphan.authorization_generation,
                                generation_started_at=database_clock_now(),
                                start_clock_health_id="legacy-untrusted",
                                start_clock_error_ms=1001,
                                start_clock_continuous=False,
                                legacy_history=True,
                            )
                        summary["orphan_connections_quarantined"] += 1

                    if (
                        app.legacy_history_unknown
                        and app.legacy_recovery_completed_at is None
                        and app.deauthorization_binding_id not in baseline_bindings
                    ):
                        if options["apply"]:
                            app.legacy_recovery_completed_at = database_clock_now()
                            app.legacy_recovery_ring_fingerprint = ring.fingerprint
                            app.save(
                                update_fields=[
                                    "legacy_recovery_completed_at",
                                    "legacy_recovery_ring_fingerprint",
                                    "updated_at",
                                ]
                            )
                        summary["app_recovery_markers_written"] += 1

                for binding in baseline_bindings:
                    app = app_by_binding[binding]
                    if (
                        app.zoom_oauth_connections.exists()
                        or app.authorization_lineages.exists()
                        or app.authorization_grants.exists()
                    ):
                        raise CommandError("clean_baseline_requires_empty_app")
                    if options["apply"]:
                        app.legacy_history_unknown = False
                        app.authorization_history_baseline_at = database_clock_now()
                        app.save(
                            update_fields=[
                                "legacy_history_unknown",
                                "authorization_history_baseline_at",
                                "updated_at",
                            ]
                        )
                    summary["clean_baselines_established"] += 1

                if not options["apply"]:
                    transaction.set_rollback(True)
        except (GrantCaptureUnavailable, IntegrityError, Project.DoesNotExist, ZoomOAuthApp.DoesNotExist):
            raise CommandError("legacy_backfill_conflict") from None

        self.stdout.write(json.dumps(summary, sort_keys=True, separators=(",", ":")))
