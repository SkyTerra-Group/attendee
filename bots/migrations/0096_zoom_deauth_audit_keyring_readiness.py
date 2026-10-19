import django.db.models.deletion
from django.db import migrations, models


def preflight_existing_history_scope(apps, schema_editor):
    """Refuse corrupt pre-0096 scope rather than blessing it with provenance."""

    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT 1
              FROM bots_zoomoauthauthorizationlineage lineage
              JOIN bots_zoomoauthapp app ON app.id = lineage.zoom_oauth_app_id
             WHERE lineage.project_id IS DISTINCT FROM app.project_id
             LIMIT 1
            """
        )
        invalid_lineage = cursor.fetchone() is not None
        cursor.execute(
            """
            SELECT 1
              FROM bots_zoomoauthauthorizationgrant grant_row
              JOIN bots_zoomoauthauthorizationlineage lineage ON lineage.id = grant_row.lineage_id
         LEFT JOIN bots_zoomoauthconnection connection ON connection.id = grant_row.live_connection_id
             WHERE grant_row.project_id IS DISTINCT FROM lineage.project_id
                OR grant_row.zoom_oauth_app_id IS DISTINCT FROM lineage.zoom_oauth_app_id
                OR grant_row.identity_digest IS DISTINCT FROM lineage.identity_digest
                OR (grant_row.live_connection_id IS NOT NULL AND (
                    connection.id IS NULL
                    OR connection.zoom_oauth_app_id IS DISTINCT FROM grant_row.zoom_oauth_app_id
                    OR connection.authorization_generation IS DISTINCT FROM grant_row.authorization_generation
                ))
             LIMIT 1
            """
        )
        invalid_grant = cursor.fetchone() is not None
    if invalid_lineage or invalid_grant:
        raise RuntimeError("zoom_deauthorization_history_preflight_failed")


def quarantine_unproven_key_provenance(apps, schema_editor):
    Lineage = apps.get_model("bots", "ZoomOAuthAuthorizationLineage")
    Grant = apps.get_model("bots", "ZoomOAuthAuthorizationGrant")
    # No pre-0096 row persisted the key ID/fingerprint that produced its
    # digest. Preserve every digest and sequence, but conservatively prevent
    # those rows from ever authorizing time-only sequence-one binding until
    # the explicit fingerprint-verified recovery command has run.
    Lineage.objects.filter(identity_audit_key_id__isnull=True).update(
        history_complete=False,
        has_prior_grant=True,
    )
    Grant.objects.filter(identity_audit_key_id__isnull=True).update(legacy_history=True)


DROP_OLD_PROVENANCE_TRIGGERS_SQL = r"""
DROP TRIGGER IF EXISTS zoom_deauth_lineage_monotone ON bots_zoomoauthauthorizationlineage;
DROP TRIGGER IF EXISTS zoom_deauth_grant_invariants ON bots_zoomoauthauthorizationgrant;
"""


KEY_PROVENANCE_TRIGGER_SQL = r"""
DROP TRIGGER IF EXISTS zoom_deauth_app_binding_immutable ON bots_zoomoauthapp;
DROP TRIGGER IF EXISTS zoom_deauth_lineage_monotone ON bots_zoomoauthauthorizationlineage;
DROP TRIGGER IF EXISTS zoom_deauth_grant_invariants ON bots_zoomoauthauthorizationgrant;
DROP TRIGGER IF EXISTS zoom_audit_key_fingerprint_immutable ON bots_zoomremovalauditkeyfingerprint;
DROP TRIGGER IF EXISTS zoom_deauth_connection_live_binding ON bots_zoomoauthconnection;

CREATE OR REPLACE FUNCTION bots_zoomdeauth_immutable_app()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.legacy_history_unknown IS NOT TRUE
           OR NEW.authorization_history_baseline_at IS NOT NULL
           OR NEW.legacy_recovery_completed_at IS NOT NULL
           OR NEW.legacy_recovery_ring_fingerprint IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom oauth app history state requires explicit bootstrap';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.deauthorization_binding_id IS DISTINCT FROM OLD.deauthorization_binding_id THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom oauth app trust binding is immutable';
    END IF;
    IF OLD.legacy_history_unknown IS FALSE AND (
       NEW.legacy_history_unknown IS DISTINCT FROM OLD.legacy_history_unknown
       OR NEW.authorization_history_baseline_at IS DISTINCT FROM OLD.authorization_history_baseline_at
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom oauth app clean history baseline is immutable';
    END IF;
    IF OLD.legacy_history_unknown IS TRUE AND NEW.legacy_history_unknown IS FALSE THEN
        IF NEW.authorization_history_baseline_at IS NULL
           OR EXISTS (SELECT 1 FROM bots_zoomoauthconnection WHERE zoom_oauth_app_id = OLD.id)
           OR EXISTS (SELECT 1 FROM bots_zoomoauthauthorizationlineage WHERE zoom_oauth_app_id = OLD.id)
           OR EXISTS (SELECT 1 FROM bots_zoomoauthauthorizationgrant WHERE zoom_oauth_app_id = OLD.id) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom oauth app clean history baseline requires an empty app';
        END IF;
    ELSIF NEW.legacy_history_unknown IS DISTINCT FROM OLD.legacy_history_unknown
          OR NEW.authorization_history_baseline_at IS DISTINCT FROM OLD.authorization_history_baseline_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom oauth app history barrier transition is invalid';
    END IF;
    IF NEW.legacy_recovery_completed_at IS NOT NULL AND (
       NEW.legacy_recovery_ring_fingerprint IS NULL
       OR NEW.legacy_recovery_ring_fingerprint !~ '^[0-9a-f]{64}$'
       OR (OLD.legacy_recovery_completed_at IS NOT NULL AND (
           NEW.legacy_recovery_completed_at IS DISTINCT FROM OLD.legacy_recovery_completed_at
           OR NEW.legacy_recovery_ring_fingerprint IS DISTINCT FROM OLD.legacy_recovery_ring_fingerprint
       ))
       OR EXISTS (
           SELECT 1 FROM bots_zoomoauthauthorizationgrant
            WHERE zoom_oauth_app_id = OLD.id
              AND identity_audit_key_id IS NULL
              AND (live_connection_id IS NOT NULL
                   OR generation_ended_at IS NULL
                   OR legacy_recovery_outcome IS NULL)
       )
       OR EXISTS (
           SELECT 1
             FROM bots_zoomoauthconnection connection
        LEFT JOIN bots_zoomoauthauthorizationgrant grant_row
               ON grant_row.live_connection_id = connection.id
            WHERE connection.zoom_oauth_app_id = OLD.id
              AND grant_row.id IS NULL
       )
       OR EXISTS (
           SELECT 1
             FROM bots_zoomoauthauthorizationgrant grant_row
             JOIN bots_zoomoauthauthorizationlineage lineage_row ON lineage_row.id = grant_row.lineage_id
        LEFT JOIN bots_zoomoauthauthorizationlineage successor ON successor.legacy_predecessor_id = lineage_row.id
            WHERE grant_row.zoom_oauth_app_id = OLD.id
              AND grant_row.identity_audit_key_id IS NULL
              AND grant_row.legacy_recovery_outcome = 'successor_linked'
              AND successor.id IS NULL
       )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom oauth app legacy recovery marker is invalid';
    END IF;
    IF NEW.legacy_recovery_completed_at IS NULL AND (
       NEW.legacy_recovery_ring_fingerprint IS NOT NULL
       OR OLD.legacy_recovery_completed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom oauth app legacy recovery marker cannot be cleared';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER zoom_deauth_app_binding_immutable
BEFORE INSERT OR UPDATE ON bots_zoomoauthapp
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_immutable_app();

CREATE OR REPLACE FUNCTION bots_zoomdeauth_connection_live_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.zoom_oauth_app_id IS DISTINCT FROM OLD.zoom_oauth_app_id
        OR NEW.object_id IS DISTINCT FROM OLD.object_id
        OR NEW.user_id IS DISTINCT FROM OLD.user_id
        OR NEW.account_id IS DISTINCT FROM OLD.account_id
        OR NEW.authorization_generation IS DISTINCT FROM OLD.authorization_generation)
       AND EXISTS (
           SELECT 1
             FROM bots_zoomoauthauthorizationgrant
            WHERE live_connection_id = OLD.id
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom oauth connection live grant binding is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER zoom_deauth_connection_live_binding
BEFORE UPDATE OF zoom_oauth_app_id, object_id, user_id, account_id, authorization_generation
ON bots_zoomoauthconnection
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_connection_live_binding();

CREATE OR REPLACE FUNCTION bots_zoomdeauth_lineage_monotone()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    app_history_unknown boolean;
    app_recovery_completed timestamptz;
    predecessor_project bigint;
    predecessor_app bigint;
    predecessor_kid varchar;
    predecessor_sequence integer;
    predecessor_complete boolean;
    predecessor_prior boolean;
    registered_fingerprint varchar;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom authorization lineage is a permanent tombstone';
    END IF;
    SELECT legacy_history_unknown, legacy_recovery_completed_at
      INTO app_history_unknown, app_recovery_completed
      FROM bots_zoomoauthapp
     WHERE id = NEW.zoom_oauth_app_id AND project_id = NEW.project_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom authorization lineage app project mismatch';
    END IF;
    IF NEW.identity_audit_key_id IS NULL THEN
        IF TG_OP = 'INSERT'
           OR NEW.identity_audit_key_fingerprint IS NOT NULL
           OR NEW.history_complete
           OR NOT NEW.has_prior_grant
           OR NOT app_history_unknown
           OR (TG_OP = 'INSERT' AND app_recovery_completed IS NOT NULL) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom unkeyed lineage is not an inert legacy tombstone';
        END IF;
    ELSE
        SELECT key_fingerprint INTO registered_fingerprint
          FROM bots_zoomremovalauditkeyfingerprint
         WHERE project_id = NEW.project_id
           AND zoom_oauth_app_id = NEW.zoom_oauth_app_id
           AND key_id = NEW.identity_audit_key_id;
        IF registered_fingerprint IS DISTINCT FROM NEW.identity_audit_key_fingerprint THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom lineage audit key fingerprint mismatch';
        END IF;
        IF app_history_unknown AND (NEW.history_complete OR NOT NEW.has_prior_grant) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom unknown app history cannot create complete lineage';
        END IF;
    END IF;
    IF NEW.legacy_predecessor_id IS NOT NULL THEN
        SELECT project_id, zoom_oauth_app_id, identity_audit_key_id, latest_grant_sequence, history_complete, has_prior_grant
          INTO predecessor_project, predecessor_app, predecessor_kid, predecessor_sequence, predecessor_complete, predecessor_prior
          FROM bots_zoomoauthauthorizationlineage WHERE id = NEW.legacy_predecessor_id;
        IF predecessor_project IS DISTINCT FROM NEW.project_id
           OR predecessor_app IS DISTINCT FROM NEW.zoom_oauth_app_id
           OR predecessor_kid IS NOT NULL
           OR predecessor_complete IS NOT FALSE
           OR predecessor_prior IS NOT TRUE
           OR NEW.identity_audit_key_id IS NULL
           OR NEW.history_complete
           OR NOT NEW.has_prior_grant
           OR NEW.latest_grant_sequence < predecessor_sequence THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom recovered lineage predecessor is invalid';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND (
       NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.zoom_oauth_app_id IS DISTINCT FROM OLD.zoom_oauth_app_id
       OR NEW.identity_digest IS DISTINCT FROM OLD.identity_digest
       OR (OLD.identity_audit_key_id IS NOT NULL AND NEW.identity_audit_key_id IS DISTINCT FROM OLD.identity_audit_key_id)
       OR (OLD.identity_audit_key_fingerprint IS NOT NULL AND NEW.identity_audit_key_fingerprint IS DISTINCT FROM OLD.identity_audit_key_fingerprint)
       OR (OLD.identity_audit_key_id IS NULL AND NEW.identity_audit_key_id IS NOT NULL)
       OR NEW.legacy_predecessor_id IS DISTINCT FROM OLD.legacy_predecessor_id
       OR NEW.history_complete IS DISTINCT FROM OLD.history_complete
       OR NEW.latest_grant_sequence < OLD.latest_grant_sequence
       OR NEW.latest_grant_sequence > OLD.latest_grant_sequence + 1
       OR (OLD.has_prior_grant AND NOT NEW.has_prior_grant)
       OR (NEW.latest_grant_sequence > 1 AND NOT NEW.has_prior_grant)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom authorization lineage is immutable and monotone';
    END IF;
    IF NEW.latest_grant_sequence > 1 AND NOT NEW.has_prior_grant THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom authorization lineage prior history missing';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER zoom_deauth_lineage_monotone
BEFORE INSERT OR UPDATE OR DELETE ON bots_zoomoauthauthorizationlineage
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_lineage_monotone();

CREATE OR REPLACE FUNCTION bots_zoomdeauth_grant_invariants()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    lineage_project bigint;
    lineage_app bigint;
    lineage_identity varchar;
    lineage_identity_kid varchar;
    lineage_identity_fingerprint varchar;
    app_history_unknown boolean;
    app_recovery_completed timestamptz;
    connection_app bigint;
    connection_generation uuid;
    canonical_project bigint;
    canonical_grant bigint;
    registered_connection_fingerprint varchar;
BEGIN
    SELECT project_id, zoom_oauth_app_id, identity_digest, identity_audit_key_id, identity_audit_key_fingerprint
      INTO lineage_project, lineage_app, lineage_identity, lineage_identity_kid, lineage_identity_fingerprint
      FROM bots_zoomoauthauthorizationlineage WHERE id = NEW.lineage_id;
    IF lineage_project IS DISTINCT FROM NEW.project_id
       OR lineage_app IS DISTINCT FROM NEW.zoom_oauth_app_id
       OR lineage_identity IS DISTINCT FROM NEW.identity_digest
       OR lineage_identity_kid IS DISTINCT FROM NEW.identity_audit_key_id
       OR lineage_identity_fingerprint IS DISTINCT FROM NEW.identity_audit_key_fingerprint THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom grant lineage scope mismatch';
    END IF;
    SELECT legacy_history_unknown, legacy_recovery_completed_at
      INTO app_history_unknown, app_recovery_completed
      FROM bots_zoomoauthapp WHERE id = NEW.zoom_oauth_app_id;
    IF NEW.legacy_recovery_outcome IS NOT NULL
       AND NEW.legacy_recovery_outcome NOT IN ('successor_linked', 'unrecoverable') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom grant legacy recovery outcome is invalid';
    END IF;
    IF NEW.identity_audit_key_id IS NULL THEN
        IF TG_OP = 'INSERT'
           OR NEW.identity_audit_key_fingerprint IS NOT NULL
           OR NEW.connection_audit_key_id IS NOT NULL
           OR NEW.connection_audit_key_fingerprint IS NOT NULL
           OR NOT NEW.legacy_history
           OR NOT app_history_unknown
           OR (app_recovery_completed IS NOT NULL AND (
               NEW.live_connection_id IS NOT NULL
               OR NEW.generation_ended_at IS NULL
               OR NEW.legacy_recovery_outcome IS NULL
           )) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom unkeyed grant is not an inert legacy tombstone';
        END IF;
    ELSIF NEW.identity_audit_key_fingerprint IS NULL
          OR NEW.connection_audit_key_id IS NULL
          OR NEW.connection_audit_key_fingerprint IS NULL
          OR NEW.legacy_recovery_outcome IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom keyed grant audit provenance is incomplete';
    END IF;
    IF NEW.connection_audit_key_id IS NOT NULL THEN
        SELECT key_fingerprint INTO registered_connection_fingerprint
          FROM bots_zoomremovalauditkeyfingerprint
         WHERE project_id = NEW.project_id
           AND zoom_oauth_app_id = NEW.zoom_oauth_app_id
           AND key_id = NEW.connection_audit_key_id;
        IF registered_connection_fingerprint IS DISTINCT FROM NEW.connection_audit_key_fingerprint THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom grant connection audit key fingerprint mismatch';
        END IF;
    END IF;
    IF NEW.live_connection_id IS NOT NULL THEN
        SELECT zoom_oauth_app_id, authorization_generation
          INTO connection_app, connection_generation
          FROM bots_zoomoauthconnection WHERE id = NEW.live_connection_id;
        IF connection_app IS DISTINCT FROM NEW.zoom_oauth_app_id
           OR connection_generation IS DISTINCT FROM NEW.authorization_generation THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom grant live connection app mismatch';
        END IF;
    END IF;
    IF NEW.canonical_removal_operation_id IS NOT NULL THEN
        SELECT project_id, authorization_grant_id INTO canonical_project, canonical_grant
          FROM bots_zoomremovaloperation WHERE id = NEW.canonical_removal_operation_id;
        IF canonical_project IS DISTINCT FROM NEW.project_id
           OR canonical_grant IS DISTINCT FROM NEW.id THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom grant canonical operation mismatch';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.binding_id IS DISTINCT FROM OLD.binding_id
        OR NEW.project_id IS DISTINCT FROM OLD.project_id
        OR NEW.zoom_oauth_app_id IS DISTINCT FROM OLD.zoom_oauth_app_id
        OR NEW.lineage_id IS DISTINCT FROM OLD.lineage_id
        OR NEW.grant_sequence IS DISTINCT FROM OLD.grant_sequence
        OR NEW.connection_digest IS DISTINCT FROM OLD.connection_digest
        OR (OLD.connection_audit_key_id IS NOT NULL AND NEW.connection_audit_key_id IS DISTINCT FROM OLD.connection_audit_key_id)
        OR (OLD.connection_audit_key_fingerprint IS NOT NULL AND NEW.connection_audit_key_fingerprint IS DISTINCT FROM OLD.connection_audit_key_fingerprint)
        OR (OLD.connection_audit_key_id IS NULL AND NEW.connection_audit_key_id IS NOT NULL)
        OR NEW.identity_digest IS DISTINCT FROM OLD.identity_digest
        OR (OLD.identity_audit_key_id IS NOT NULL AND NEW.identity_audit_key_id IS DISTINCT FROM OLD.identity_audit_key_id)
        OR (OLD.identity_audit_key_fingerprint IS NOT NULL AND NEW.identity_audit_key_fingerprint IS DISTINCT FROM OLD.identity_audit_key_fingerprint)
        OR (OLD.identity_audit_key_id IS NULL AND NEW.identity_audit_key_id IS NOT NULL)
        OR (OLD.legacy_recovery_outcome IS NOT NULL AND NEW.legacy_recovery_outcome IS DISTINCT FROM OLD.legacy_recovery_outcome)
        OR (OLD.legacy_recovery_outcome IS NULL AND NEW.legacy_recovery_outcome IS NOT NULL
            AND NEW.legacy_recovery_outcome NOT IN ('successor_linked', 'unrecoverable'))
        OR NEW.authorization_generation IS DISTINCT FROM OLD.authorization_generation
        OR NEW.generation_started_at IS DISTINCT FROM OLD.generation_started_at
        OR NEW.start_clock_health_id IS DISTINCT FROM OLD.start_clock_health_id
        OR NEW.start_clock_error_ms IS DISTINCT FROM OLD.start_clock_error_ms
        OR NEW.start_clock_continuous IS DISTINCT FROM OLD.start_clock_continuous
        OR NEW.legacy_history IS DISTINCT FROM OLD.legacy_history
        OR (OLD.generation_ended_at IS NOT NULL AND NEW.generation_ended_at IS DISTINCT FROM OLD.generation_ended_at)
        OR (OLD.end_clock_health_id IS NOT NULL AND NEW.end_clock_health_id IS DISTINCT FROM OLD.end_clock_health_id)
        OR (OLD.end_clock_error_ms IS NOT NULL AND NEW.end_clock_error_ms IS DISTINCT FROM OLD.end_clock_error_ms)
        OR (OLD.end_clock_continuous IS NOT NULL AND NEW.end_clock_continuous IS DISTINCT FROM OLD.end_clock_continuous)
        OR (OLD.live_connection_id IS NULL AND NEW.live_connection_id IS NOT NULL)
        OR (OLD.live_connection_id IS NOT NULL AND NEW.live_connection_id IS NOT NULL AND NEW.live_connection_id IS DISTINCT FROM OLD.live_connection_id)
        OR (OLD.canonical_removal_operation_id IS NOT NULL AND NEW.canonical_removal_operation_id IS NOT NULL
            AND NEW.canonical_removal_operation_id IS DISTINCT FROM OLD.canonical_removal_operation_id)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom authorization grant immutable fields changed';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER zoom_deauth_grant_invariants
BEFORE INSERT OR UPDATE ON bots_zoomoauthauthorizationgrant
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_grant_invariants();

CREATE OR REPLACE FUNCTION bots_zoomdeauth_audit_key_fingerprint_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom audit key fingerprint registry is permanent';
    END IF;
    IF NEW.key_id !~ '^[A-Za-z0-9._:/-]+$'
       OR NEW.key_fingerprint !~ '^[0-9a-f]{64}$'
       OR NEW.algorithm != 'HMAC-SHA-256'
       OR NEW.derivation_domain != 'attendee-zoom-removal-audit-v1'
       OR NEW.derivation_version != 1
       OR NOT EXISTS (
           SELECT 1 FROM bots_zoomoauthapp
            WHERE id = NEW.zoom_oauth_app_id AND project_id = NEW.project_id
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom audit key fingerprint scope is invalid';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER zoom_audit_key_fingerprint_immutable
BEFORE INSERT OR UPDATE OR DELETE ON bots_zoomremovalauditkeyfingerprint
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_audit_key_fingerprint_immutable();
"""


KEY_PROVENANCE_TRIGGER_REVERSE_SQL = r"""
DROP TRIGGER IF EXISTS zoom_deauth_app_binding_immutable ON bots_zoomoauthapp;
DROP TRIGGER IF EXISTS zoom_deauth_lineage_monotone ON bots_zoomoauthauthorizationlineage;
DROP TRIGGER IF EXISTS zoom_deauth_grant_invariants ON bots_zoomoauthauthorizationgrant;
DROP TRIGGER IF EXISTS zoom_audit_key_fingerprint_immutable ON bots_zoomremovalauditkeyfingerprint;
DROP TRIGGER IF EXISTS zoom_deauth_connection_live_binding ON bots_zoomoauthconnection;
DROP FUNCTION IF EXISTS bots_zoomdeauth_audit_key_fingerprint_immutable();
DROP FUNCTION IF EXISTS bots_zoomdeauth_connection_live_binding();

CREATE OR REPLACE FUNCTION bots_zoomdeauth_immutable_app()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.deauthorization_binding_id IS DISTINCT FROM OLD.deauthorization_binding_id THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom oauth app trust binding is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER zoom_deauth_app_binding_immutable BEFORE UPDATE ON bots_zoomoauthapp
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_immutable_app();

CREATE OR REPLACE FUNCTION bots_zoomdeauth_lineage_monotone()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM bots_zoomoauthapp WHERE id = NEW.zoom_oauth_app_id AND project_id = NEW.project_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom authorization lineage app project mismatch';
    END IF;
    IF TG_OP = 'UPDATE' AND (
       NEW.project_id IS DISTINCT FROM OLD.project_id OR NEW.zoom_oauth_app_id IS DISTINCT FROM OLD.zoom_oauth_app_id
       OR NEW.identity_digest IS DISTINCT FROM OLD.identity_digest OR NEW.history_complete IS DISTINCT FROM OLD.history_complete
       OR NEW.latest_grant_sequence < OLD.latest_grant_sequence OR NEW.latest_grant_sequence > OLD.latest_grant_sequence + 1
       OR (OLD.has_prior_grant AND NOT NEW.has_prior_grant) OR (NEW.latest_grant_sequence > 1 AND NOT NEW.has_prior_grant)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom authorization lineage is immutable and monotone';
    END IF;
    IF NEW.latest_grant_sequence > 1 AND NOT NEW.has_prior_grant THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom authorization lineage prior history missing';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER zoom_deauth_lineage_monotone BEFORE INSERT OR UPDATE ON bots_zoomoauthauthorizationlineage
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_lineage_monotone();

CREATE OR REPLACE FUNCTION bots_zoomdeauth_grant_invariants()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE lineage_project bigint; lineage_app bigint; lineage_identity varchar; connection_app bigint; connection_generation uuid; canonical_project bigint; canonical_grant bigint;
BEGIN
    SELECT project_id, zoom_oauth_app_id, identity_digest INTO lineage_project, lineage_app, lineage_identity FROM bots_zoomoauthauthorizationlineage WHERE id = NEW.lineage_id;
    IF lineage_project IS DISTINCT FROM NEW.project_id OR lineage_app IS DISTINCT FROM NEW.zoom_oauth_app_id OR lineage_identity IS DISTINCT FROM NEW.identity_digest THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom grant lineage scope mismatch';
    END IF;
    IF NEW.live_connection_id IS NOT NULL THEN
        SELECT zoom_oauth_app_id, authorization_generation INTO connection_app, connection_generation FROM bots_zoomoauthconnection WHERE id = NEW.live_connection_id;
        IF connection_app IS DISTINCT FROM NEW.zoom_oauth_app_id OR connection_generation IS DISTINCT FROM NEW.authorization_generation THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom grant live connection app mismatch';
        END IF;
    END IF;
    IF NEW.canonical_removal_operation_id IS NOT NULL THEN
        SELECT project_id, authorization_grant_id INTO canonical_project, canonical_grant FROM bots_zoomremovaloperation WHERE id = NEW.canonical_removal_operation_id;
        IF canonical_project IS DISTINCT FROM NEW.project_id OR canonical_grant IS DISTINCT FROM NEW.id THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom grant canonical operation mismatch';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.binding_id IS DISTINCT FROM OLD.binding_id OR NEW.project_id IS DISTINCT FROM OLD.project_id
        OR NEW.zoom_oauth_app_id IS DISTINCT FROM OLD.zoom_oauth_app_id OR NEW.lineage_id IS DISTINCT FROM OLD.lineage_id
        OR NEW.grant_sequence IS DISTINCT FROM OLD.grant_sequence OR NEW.connection_digest IS DISTINCT FROM OLD.connection_digest
        OR NEW.identity_digest IS DISTINCT FROM OLD.identity_digest OR NEW.authorization_generation IS DISTINCT FROM OLD.authorization_generation
        OR NEW.generation_started_at IS DISTINCT FROM OLD.generation_started_at OR NEW.start_clock_health_id IS DISTINCT FROM OLD.start_clock_health_id
        OR NEW.start_clock_error_ms IS DISTINCT FROM OLD.start_clock_error_ms OR NEW.start_clock_continuous IS DISTINCT FROM OLD.start_clock_continuous
        OR NEW.legacy_history IS DISTINCT FROM OLD.legacy_history
        OR (OLD.generation_ended_at IS NOT NULL AND NEW.generation_ended_at IS DISTINCT FROM OLD.generation_ended_at)
        OR (OLD.end_clock_health_id IS NOT NULL AND NEW.end_clock_health_id IS DISTINCT FROM OLD.end_clock_health_id)
        OR (OLD.end_clock_error_ms IS NOT NULL AND NEW.end_clock_error_ms IS DISTINCT FROM OLD.end_clock_error_ms)
        OR (OLD.end_clock_continuous IS NOT NULL AND NEW.end_clock_continuous IS DISTINCT FROM OLD.end_clock_continuous)
        OR (OLD.live_connection_id IS NULL AND NEW.live_connection_id IS NOT NULL)
        OR (OLD.live_connection_id IS NOT NULL AND NEW.live_connection_id IS NOT NULL AND NEW.live_connection_id IS DISTINCT FROM OLD.live_connection_id)
        OR (OLD.canonical_removal_operation_id IS NOT NULL AND NEW.canonical_removal_operation_id IS NOT NULL AND NEW.canonical_removal_operation_id IS DISTINCT FROM OLD.canonical_removal_operation_id)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom authorization grant immutable fields changed';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER zoom_deauth_grant_invariants BEFORE INSERT OR UPDATE ON bots_zoomoauthauthorizationgrant
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_grant_invariants();
"""


class Migration(migrations.Migration):
    dependencies = [("bots", "0095_zoom_deauth_operation_event_digest_consistency")]

    operations = [
        migrations.RunPython(preflight_existing_history_scope, migrations.RunPython.noop),
        migrations.AddField(
            model_name="zoomoauthapp",
            name="authorization_history_baseline_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="zoomoauthapp",
            name="legacy_history_unknown",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="zoomoauthapp",
            name="legacy_recovery_completed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="zoomoauthapp",
            name="legacy_recovery_ring_fingerprint",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="zoomoauthauthorizationlineage",
            name="identity_audit_key_id",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="zoomoauthauthorizationlineage",
            name="identity_audit_key_fingerprint",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="zoomoauthauthorizationlineage",
            name="legacy_predecessor",
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="recovered_lineage", to="bots.zoomoauthauthorizationlineage"),
        ),
        migrations.AddField(
            model_name="zoomoauthauthorizationgrant",
            name="connection_audit_key_id",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="zoomoauthauthorizationgrant",
            name="connection_audit_key_fingerprint",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="zoomoauthauthorizationgrant",
            name="identity_audit_key_id",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="zoomoauthauthorizationgrant",
            name="identity_audit_key_fingerprint",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="zoomoauthauthorizationgrant",
            name="legacy_recovery_outcome",
            field=models.CharField(
                blank=True,
                choices=[("successor_linked", "Successor linked"), ("unrecoverable", "Unrecoverable")],
                max_length=32,
                null=True,
            ),
        ),
        migrations.CreateModel(
            name="ZoomRemovalAuditKeyFingerprint",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("key_id", models.CharField(max_length=64)),
                ("key_fingerprint", models.CharField(max_length=64)),
                ("algorithm", models.CharField(default="HMAC-SHA-256", max_length=32)),
                (
                    "derivation_domain",
                    models.CharField(default="attendee-zoom-removal-audit-v1", max_length=64),
                ),
                ("derivation_version", models.PositiveSmallIntegerField(default=1)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="zoom_removal_audit_key_fingerprints",
                        to="bots.project",
                    ),
                ),
                (
                    "zoom_oauth_app",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="audit_key_fingerprints",
                        to="bots.zoomoauthapp",
                    ),
                ),
            ],
        ),
        migrations.RunSQL(DROP_OLD_PROVENANCE_TRIGGERS_SQL, reverse_sql=migrations.RunSQL.noop),
        migrations.RunPython(quarantine_unproven_key_provenance, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="zoomoauthapp",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(legacy_history_unknown=True, authorization_history_baseline_at__isnull=True),
                    models.Q(legacy_history_unknown=False, authorization_history_baseline_at__isnull=False),
                    _connector="OR",
                ),
                name="zoom_app_history_baseline_shape",
            ),
        ),
        migrations.AddConstraint(
            model_name="zoomoauthapp",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(legacy_recovery_completed_at__isnull=True, legacy_recovery_ring_fingerprint__isnull=True),
                    models.Q(legacy_recovery_completed_at__isnull=False, legacy_recovery_ring_fingerprint__isnull=False),
                    _connector="OR",
                ),
                name="zoom_app_legacy_recovery_marker_shape",
            ),
        ),
        migrations.AddConstraint(
            model_name="zoomoauthauthorizationlineage",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("identity_audit_key_fingerprint__isnull", False), ("identity_audit_key_id__isnull", False)),
                    models.Q(
                        ("has_prior_grant", True),
                        ("history_complete", False),
                        ("identity_audit_key_fingerprint__isnull", True),
                        ("identity_audit_key_id__isnull", True),
                    ),
                    _connector="OR",
                ),
                name="zoom_lineage_unkeyed_is_incomplete",
            ),
        ),
        migrations.AddConstraint(
            model_name="zoomoauthauthorizationgrant",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(live_connection__isnull=True)
                    | models.Q(generation_ended_at__isnull=True)
                ),
                name="zoom_grant_live_connection_is_open",
            ),
        ),
        migrations.AddConstraint(
            model_name="zoomoauthauthorizationgrant",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(
                        connection_audit_key_fingerprint__isnull=False,
                        connection_audit_key_id__isnull=False,
                        identity_audit_key_fingerprint__isnull=False,
                        identity_audit_key_id__isnull=False,
                        legacy_recovery_outcome__isnull=True,
                    ),
                    models.Q(
                        connection_audit_key_fingerprint__isnull=True,
                        connection_audit_key_id__isnull=True,
                        identity_audit_key_fingerprint__isnull=True,
                        identity_audit_key_id__isnull=True,
                        legacy_history=True,
                    ),
                    _connector="OR",
                ),
                name="zoom_grant_audit_key_ids_complete",
            ),
        ),
        migrations.AddConstraint(
            model_name="zoomoauthauthorizationgrant",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(legacy_recovery_outcome__isnull=True)
                    | models.Q(legacy_recovery_outcome__in=["successor_linked", "unrecoverable"])
                ),
                name="zoom_grant_legacy_recovery_outcome_valid",
            ),
        ),
        migrations.AddConstraint(
            model_name="zoomremovalauditkeyfingerprint",
            constraint=models.UniqueConstraint(
                fields=("project", "zoom_oauth_app", "key_id"),
                name="zoom_audit_key_registry_scope_kid_unique",
            ),
        ),
        migrations.AddConstraint(
            model_name="zoomremovalauditkeyfingerprint",
            constraint=models.UniqueConstraint(
                fields=("key_fingerprint",),
                name="zoom_audit_key_registry_fingerprint_unique",
            ),
        ),
        migrations.RunSQL(KEY_PROVENANCE_TRIGGER_SQL, reverse_sql=KEY_PROVENANCE_TRIGGER_REVERSE_SQL),
    ]
