from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from logs.reports import generate_report
from django.utils.dateparse import parse_date
from logs.models import Utilisateur


class Command(BaseCommand):
    help = 'Génère un rapport pour une période donnée et l\'enregistre dans la base'

    def add_arguments(self, parser):
        parser.add_argument('date_debut', type=str, help='Date de début au format AAAA-MM-JJ')
        parser.add_argument('date_fin', type=str, help='Date de fin au format AAAA-MM-JJ')
        parser.add_argument('--utilisateur', type=int, required=True, help='ID de l\'utilisateur qui génère le rapport')
        parser.add_argument('--output-dir', type=str, default='.', help='Répertoire de sortie du fichier CSV')
        parser.add_argument('--type-rapport', type=str, default='Rapport Périodique', help='Type de rapport')

    def handle(self, *args, **options):
        date_debut = parse_date(options['date_debut'])
        date_fin = parse_date(options['date_fin'])
        if not date_debut or not date_fin:
            raise CommandError('Dates invalides : utilisez le format AAAA-MM-JJ.')

        utilisateur = Utilisateur.objects.filter(id_utilisateur=options['utilisateur']).first()
        if not utilisateur:
            raise CommandError('Utilisateur non trouvé.')

        rapport = generate_report(
            date_debut,
            date_fin,
            utilisateur=utilisateur,
            output_dir=options['output_dir'],
            type_rapport=options['type_rapport'],
        )

        self.stdout.write(self.style.SUCCESS(
            f"Rapport généré : {rapport.chemin_fichier} (ID {rapport.id_rapport})"
        ))
