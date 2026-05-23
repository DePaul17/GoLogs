from django.core.management.base import BaseCommand, CommandError
from logs.utils import parse_log_line
from logs.models import SourceLog, Serveur, LogEntree
from pathlib import Path
from django.utils import timezone


class Command(BaseCommand):
    help = 'Importe un fichier de logs et normalise les entrées dans la base'

    def add_arguments(self, parser):
        parser.add_argument('fichier', type=str, help='Chemin du fichier de logs à importer')
        parser.add_argument('--source', type=int, help='ID de la source (SourceLog)')
        parser.add_argument('--serveur', type=int, help='ID du serveur (Serveur)')

    def handle(self, *args, **options):
        chemin = Path(options['fichier'])
        if not chemin.exists():
            raise CommandError(f"Fichier non trouvé: {chemin}")

        source = None
        serveur = None
        if options.get('source'):
            source = SourceLog.objects.filter(id_source=options['source']).first()
            if not source:
                raise CommandError('Source non trouvée')

        if options.get('serveur'):
            serveur = Serveur.objects.filter(id_serveur=options['serveur']).first()
            if not serveur:
                raise CommandError('Serveur non trouvé')

        created = 0
        with chemin.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = parse_log_line(line)
                if not parsed:
                    continue

                le = LogEntree(
                    source=source,
                    serveur=serveur,
                    horodatage=parsed['horodatage'] or timezone.now(),
                    niveau=parsed['niveau'] or 'INFO',
                    service=parsed.get('service'),
                    message=parsed.get('message')[:255],
                    statut_traitement='NOUVEAU',
                    date_insertion=timezone.now(),
                )
                le.save()
                created += 1

        self.stdout.write(self.style.SUCCESS(f"Import terminé, {created} entrées créées."))
