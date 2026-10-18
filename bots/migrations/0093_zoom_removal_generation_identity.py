from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("bots", "0092_zoom_removal_fences"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="zoomremovaloperation",
            name="unique_zoom_removal_target_per_project",
        ),
        migrations.AddConstraint(
            model_name="zoomremovaloperation",
            constraint=models.UniqueConstraint(
                condition=models.Q(operation_type="purge_bot"),
                fields=("project", "operation_type", "target_digest"),
                name="unique_zoom_purge_target_per_project",
            ),
        ),
        migrations.AddConstraint(
            model_name="zoomremovaloperation",
            constraint=models.UniqueConstraint(
                condition=models.Q(operation_type="revoke_connection"),
                fields=("project", "operation_type", "target_digest", "target_generation"),
                name="unique_zoom_revoke_target_generation",
                nulls_distinct=False,
            ),
        ),
    ]
