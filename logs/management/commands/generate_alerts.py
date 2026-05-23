from django.core.management.base import BaseCommand, CommandError
from logs.alerting import generate_alerts_for_undetected_anomalies


class Command(BaseCommand):
    help = 'Génère des alertes automatiques à partir des anomalies existantes'

    def handle(self, *args, **options):
        created = generate_alerts_for_undetected_anomalies()
        if not created:
            self.stdout.write(self.style.WARNING('Aucune nouvelle alerte générée.'))
            return

        self.stdout.write(self.style.SUCCESS(f"{len(created)} alertes générées."))
