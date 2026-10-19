from django.db import migrations


def assert_existing_operation_event_digests_are_consistent(apps, schema_editor):
    """Refuse to install the trigger over contradictory retained evidence."""

    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT operation.id
              FROM bots_zoomremovaloperation operation
              LEFT JOIN bots_zoomdeauthorizationeventbinding binding
                ON binding.operation_id = operation.id
             WHERE (
                       operation.verified_deauthorization_event_digest IS NOT NULL
                       AND (
                           binding.id IS NULL
                           OR operation.verified_deauthorization_event_digest
                              IS DISTINCT FROM binding.event_digest
                       )
                   )
                OR (
                       operation.signed_deauthorization_settled_at IS NOT NULL
                       AND (
                           operation.verified_deauthorization_event_digest IS NULL
                           OR operation.verified_deauthorization_at IS NULL
                           OR binding.id IS NULL
                           OR operation.verified_deauthorization_event_digest
                              IS DISTINCT FROM binding.event_digest
                       )
                   )
             LIMIT 1
            """
        )
        contradictory_operation = cursor.fetchone()
    if contradictory_operation is not None:
        raise RuntimeError(
            "zoom deauthorization operation/event digest consistency preflight failed"
        )

    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT resolution.id
              FROM bots_zoomdeauthorizationtargetresolution resolution
              JOIN bots_zoomdeauthorizationeventbinding binding
                ON binding.id = resolution.event_binding_id
             WHERE resolution.event_digest IS DISTINCT FROM binding.event_digest
             LIMIT 1
            """
        )
        contradictory_resolution = cursor.fetchone()
    if contradictory_resolution is not None:
        raise RuntimeError(
            "zoom deauthorization resolution/event digest consistency preflight failed"
        )


OPERATION_EVENT_DIGEST_TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION bots_zoomdeauth_operation_event_digest_consistent()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    binding_digest varchar;
    operation_digest varchar;
    operation_verified_at timestamptz;
    operation_signed_at timestamptz;
BEGIN
    IF TG_TABLE_NAME = 'bots_zoomremovaloperation' THEN
        IF NEW.signed_deauthorization_settled_at IS NOT NULL
           AND (
               NEW.verified_deauthorization_event_digest IS NULL
               OR NEW.verified_deauthorization_at IS NULL
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'zoom signed deauthorization evidence is incomplete';
        END IF;

        IF NEW.verified_deauthorization_event_digest IS NOT NULL
           OR NEW.signed_deauthorization_settled_at IS NOT NULL THEN
            SELECT event_digest
              INTO binding_digest
              FROM bots_zoomdeauthorizationeventbinding
             WHERE operation_id = NEW.id;
            IF NOT FOUND
               OR NEW.verified_deauthorization_event_digest
                  IS DISTINCT FROM binding_digest THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'zoom operation event digest does not match its binding';
            END IF;
        END IF;
    ELSIF TG_TABLE_NAME = 'bots_zoomdeauthorizationeventbinding' THEN
        IF NEW.operation_id IS NOT NULL THEN
            SELECT verified_deauthorization_event_digest,
                   verified_deauthorization_at,
                   signed_deauthorization_settled_at
              INTO operation_digest, operation_verified_at, operation_signed_at
              FROM bots_zoomremovaloperation
             WHERE id = NEW.operation_id;
            IF FOUND THEN
                IF operation_digest IS NOT NULL
                   AND operation_digest IS DISTINCT FROM NEW.event_digest THEN
                    RAISE EXCEPTION USING ERRCODE = '23514',
                        MESSAGE = 'zoom binding event digest does not match its operation';
                END IF;
                IF operation_signed_at IS NOT NULL
                   AND (
                       operation_digest IS NULL
                       OR operation_verified_at IS NULL
                       OR operation_digest IS DISTINCT FROM NEW.event_digest
                   ) THEN
                    RAISE EXCEPTION USING ERRCODE = '23514',
                        MESSAGE = 'zoom signed deauthorization binding evidence is incomplete';
                END IF;
            END IF;
        END IF;
    ELSIF TG_TABLE_NAME = 'bots_zoomdeauthorizationtargetresolution' THEN
        IF NEW.event_binding_id IS NOT NULL THEN
            SELECT event_digest
              INTO binding_digest
              FROM bots_zoomdeauthorizationeventbinding
             WHERE id = NEW.event_binding_id;
            IF NOT FOUND OR NEW.event_digest IS DISTINCT FROM binding_digest THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'zoom resolution event digest does not match its binding';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER zoom_deauth_operation_event_digest_consistency
BEFORE INSERT OR UPDATE OF verified_deauthorization_event_digest,
                           verified_deauthorization_at,
                           signed_deauthorization_settled_at
ON bots_zoomremovaloperation
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_operation_event_digest_consistent();

CREATE TRIGGER zoom_deauth_binding_event_digest_consistency
BEFORE INSERT OR UPDATE OF operation_id, event_digest
ON bots_zoomdeauthorizationeventbinding
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_operation_event_digest_consistent();

CREATE TRIGGER zoom_deauth_resolution_event_digest_consistency
BEFORE INSERT OR UPDATE OF event_binding_id, event_digest
ON bots_zoomdeauthorizationtargetresolution
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_operation_event_digest_consistent();

CREATE OR REPLACE FUNCTION bots_zoomdeauth_old_operation_retains_event_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    operation_digest varchar;
    operation_verified_at timestamptz;
    operation_signed_at timestamptz;
BEGIN
    IF OLD.operation_id IS NULL THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    SELECT verified_deauthorization_event_digest,
           verified_deauthorization_at,
           signed_deauthorization_settled_at
      INTO operation_digest, operation_verified_at, operation_signed_at
      FROM bots_zoomremovaloperation
     WHERE id = OLD.operation_id;
    IF FOUND AND operation_signed_at IS NOT NULL AND (
        operation_digest IS NULL
        OR operation_verified_at IS NULL
        OR NOT EXISTS (
            SELECT 1
              FROM bots_zoomdeauthorizationeventbinding
             WHERE operation_id = OLD.operation_id
               AND event_digest = operation_digest
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'zoom signed deauthorization operation lost its event binding';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER zoom_deauth_old_operation_retains_event_binding
AFTER UPDATE OR DELETE ON bots_zoomdeauthorizationeventbinding
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_old_operation_retains_event_binding();

CREATE OR REPLACE FUNCTION bots_zoomdeauth_event_binding_delete_forbidden()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514',
        MESSAGE = 'zoom deauthorization event binding is a permanent tombstone';
END;
$$;

CREATE TRIGGER zoom_deauth_event_binding_delete_forbidden
BEFORE DELETE ON bots_zoomdeauthorizationeventbinding
FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_event_binding_delete_forbidden();
"""


OPERATION_EVENT_DIGEST_TRIGGER_REVERSE_SQL = """
DROP TRIGGER IF EXISTS zoom_deauth_event_binding_delete_forbidden
ON bots_zoomdeauthorizationeventbinding;
DROP TRIGGER IF EXISTS zoom_deauth_old_operation_retains_event_binding
ON bots_zoomdeauthorizationeventbinding;
DROP TRIGGER IF EXISTS zoom_deauth_resolution_event_digest_consistency
ON bots_zoomdeauthorizationtargetresolution;
DROP TRIGGER IF EXISTS zoom_deauth_binding_event_digest_consistency
ON bots_zoomdeauthorizationeventbinding;
DROP TRIGGER IF EXISTS zoom_deauth_operation_event_digest_consistency
ON bots_zoomremovaloperation;
DROP FUNCTION IF EXISTS bots_zoomdeauth_event_binding_delete_forbidden();
DROP FUNCTION IF EXISTS bots_zoomdeauth_old_operation_retains_event_binding();
DROP FUNCTION IF EXISTS bots_zoomdeauth_operation_event_digest_consistent();
"""


class Migration(migrations.Migration):
    dependencies = [
        ("bots", "0094_zoom_deauthorization_trust"),
    ]

    operations = [
        migrations.RunPython(
            assert_existing_operation_event_digests_are_consistent,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.RunSQL(
            OPERATION_EVENT_DIGEST_TRIGGER_SQL,
            reverse_sql=OPERATION_EVENT_DIGEST_TRIGGER_REVERSE_SQL,
        ),
    ]
