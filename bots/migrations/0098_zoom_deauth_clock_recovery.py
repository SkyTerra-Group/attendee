import uuid

import django.db.models.deletion
from django.db import migrations, models

RECOVERY_FUNCTION_BODY = """
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom clock recovery immutable';
    END IF;
    IF NEW.recovery_policy <> 'single-open-first-grant-deferred-v1' OR NOT EXISTS (
        SELECT 1
          FROM bots_zoomdeauthorizationtargetresolution resolution
          JOIN bots_zoomdeauthorizationeventbinding binding
            ON binding.id = NEW.event_binding_id
          JOIN bots_zoomremovaloperationidentifier identifier
            ON identifier.operation_id = binding.operation_id AND identifier.role = 'canonical'
         WHERE resolution.id = NEW.resolution_id
           AND resolution.outcome IN ('clock_untrusted', 'delayed_event_unbound')
           AND resolution.event_binding_id IS NULL AND resolution.operation_id IS NULL
           AND resolution.project_id = binding.project_id
           AND resolution.zoom_oauth_app_id = binding.zoom_oauth_app_id
           AND resolution.event_digest = binding.event_digest
           AND binding.temporal_policy = NEW.recovery_policy
           AND binding.binding_evidence_digest = NEW.evidence_digest
           AND identifier.identifier_uuid = NEW.canonical_operation_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'zoom clock recovery scope mismatch';
    END IF;
    RETURN NEW;
END;
"""


class Migration(migrations.Migration):
    dependencies = [('bots', '0097_zoom_deauth_grant_clock_sample')]
    operations = [
        migrations.CreateModel(
            name='ZoomDeauthorizationClockRecovery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('recovery_id', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('canonical_operation_id', models.UUIDField()),
                ('recovery_policy', models.CharField(max_length=64)),
                ('evidence_digest', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('resolution', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='clock_recovery', to='bots.zoomdeauthorizationtargetresolution')),
                ('event_binding', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='clock_recovery', to='bots.zoomdeauthorizationeventbinding')),
            ],
        ),
        migrations.RemoveConstraint(model_name='zoomdeauthorizationassertionreceipt', name='zoom_assertion_receipt_target_matches_purpose'),
        migrations.AddConstraint(
            model_name='zoomdeauthorizationassertionreceipt',
            constraint=models.CheckConstraint(
                condition=(models.Q(purpose='zoom-deauthorization:settle', operation__isnull=False, resolution__isnull=True)
                    | models.Q(purpose__in=['zoom-deauthorization:resolve', 'zoom-deauthorization:recover'], operation__isnull=True, resolution__isnull=False)),
                name='zoom_assertion_receipt_target_matches_purpose',
            ),
        ),
        migrations.RunSQL(
            "CREATE FUNCTION bots_zoomdeauth_clock_recovery_immutable() RETURNS trigger LANGUAGE plpgsql AS $$" + RECOVERY_FUNCTION_BODY + "$$;"
            "CREATE TRIGGER zoom_deauth_clock_recovery_immutable BEFORE INSERT OR UPDATE OR DELETE ON bots_zoomdeauthorizationclockrecovery "
            "FOR EACH ROW EXECUTE FUNCTION bots_zoomdeauth_clock_recovery_immutable();",
            "DROP TRIGGER zoom_deauth_clock_recovery_immutable ON bots_zoomdeauthorizationclockrecovery; DROP FUNCTION bots_zoomdeauth_clock_recovery_immutable();",
        ),
    ]
