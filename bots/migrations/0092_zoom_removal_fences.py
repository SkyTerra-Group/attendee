import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("bots", "0091_zoomremovaloperation"),
    ]

    operations = [
        migrations.AddField(
            model_name="zoomoauthconnection",
            name="authorization_generation",
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.AlterField(
            model_name="zoomoauthconnection",
            name="state",
            field=models.IntegerField(
                choices=[(1, "Connected"), (2, "Disconnected"), (3, "Removing")],
                default=1,
            ),
        ),
        migrations.AddField(
            model_name="zoomremovaloperation",
            name="target_generation",
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="bot",
            name="removal_requested_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="bot",
            name="runtime_generation",
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
        migrations.AddField(
            model_name="bot",
            name="runtime_backend",
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
        migrations.AddField(
            model_name="bot",
            name="runtime_identifier",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name="bot",
            name="runtime_launch_started_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="bot",
            name="runtime_launch_completed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="bot",
            name="runtime_launch_in_progress",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="bot",
            name="runtime_absence_confirmed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="bot",
            name="runtime_absence_generation",
            field=models.UUIDField(blank=True, null=True),
        ),
    ]
