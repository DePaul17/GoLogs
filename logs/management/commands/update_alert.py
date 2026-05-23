from django.core.management.base import BaseCommand, CommandError
from logs.alerting import update_alert_status


class Command(BaseCommand):
    help = 'Met à jour le statut d\'une alerte existante'

    def add_arguments(self, parser):
        parser.add_argument('id_alerte', type=int, help='ID de l\'alerte à mettre à jour')
        parser.add_argument('statut', type=str, help='Nouveau statut de l\'alerte')

    def handle(self, *args, **options):
        try:
            alert = update_alert_status(options['id_alerte'], options['statut'])
        except ValueError as exc:
            raise CommandError(str(exc))

        self.stdout.write(self.style.SUCCESS(f"Alerte {alert.id_alerte} mise à jour en statut {alert.statut}."))
