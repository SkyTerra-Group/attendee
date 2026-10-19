import json

from django.core.management.base import BaseCommand, CommandError

from bots.zoom_deauthorization_readiness import DeauthorizationReadinessError, collect_readiness


class Command(BaseCommand):
    help = "Fail-closed, read-only readiness check for signed Zoom deauthorization"

    def handle(self, *args, **options):
        try:
            report = collect_readiness()
        except DeauthorizationReadinessError as error:
            raise CommandError(error.code) from None
        self.stdout.write(json.dumps(report.safe_dict(), sort_keys=True, separators=(",", ":")))
