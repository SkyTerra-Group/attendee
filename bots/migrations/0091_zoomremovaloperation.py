import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("bots", "0090_instancehealthalertsstate"),
    ]

    operations = [
        migrations.CreateModel(
            name="ZoomRemovalOperation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("operation_id", models.UUIDField()),
                (
                    "operation_type",
                    models.CharField(
                        choices=[("revoke_connection", "Revoke connection"), ("purge_bot", "Purge bot")],
                        max_length=32,
                    ),
                ),
                (
                    "source",
                    models.CharField(
                        blank=True,
                        choices=[("skyterra_initiated", "SkyTerra initiated"), ("zoom_deauthorization", "Zoom deauthorization")],
                        max_length=32,
                        null=True,
                    ),
                ),
                ("target_digest", models.CharField(max_length=64)),
                ("target_object_id", models.CharField(blank=True, max_length=32, null=True)),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("pending_active", "Pending active bot"),
                            ("revoke_unknown", "Revoke result unknown"),
                            ("revoked", "Revoked"),
                            ("data_deleted", "Sensitive data deleted"),
                            ("purge_unknown", "Purge result unknown"),
                            ("purged", "Purged"),
                            ("not_found_unproved", "Target absence unproved"),
                        ],
                        default="pending",
                        max_length=32,
                    ),
                ),
                (
                    "phase",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("storage_verified", "Storage absence verified"),
                            ("data_deleted", "Existing delete_data completed"),
                            ("database_deleted", "Database rows deleted"),
                            ("complete", "Complete"),
                        ],
                        default="pending",
                        max_length=32,
                    ),
                ),
                ("failure_code", models.CharField(blank=True, max_length=64, null=True)),
                ("storage_manifest", models.JSONField(blank=True, default=dict)),
                ("lease_token", models.UUIDField(blank=True, null=True)),
                ("lease_expires_at", models.DateTimeField(blank=True, null=True)),
                ("attempt_count", models.PositiveIntegerField(default=0)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("expires_at", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="zoom_removal_operations",
                        to="bots.project",
                    ),
                ),
            ],
            options={
                "indexes": [models.Index(fields=["project", "operation_id"], name="zoom_remove_project_op_idx")],
                "constraints": [
                    models.UniqueConstraint(fields=("project", "operation_id"), name="unique_zoom_removal_operation_id_per_project"),
                    models.UniqueConstraint(fields=("project", "operation_type", "target_digest"), name="unique_zoom_removal_target_per_project"),
                ],
            },
        ),
    ]
