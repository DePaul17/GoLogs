from django.core.management.base import BaseCommand
from django.utils import timezone

from logs.models import Alerte, Anomalie, LogEntree, Serveur, SourceLog


class Command(BaseCommand):
    help = 'Insère des données de démonstration pour tester le tableau de bord admin'

    def handle(self, *args, **options):
        source, _ = SourceLog.objects.get_or_create(
            nom_source='API principale',
            defaults={
                'type_source': 'application',
                'adresse_ip': '10.0.0.1',
                'description': 'Logs des requêtes HTTP',
                'statut': 'ACTIF',
                'date_ajout': timezone.now(),
            },
        )
        demo_serveurs = [
            ('srv-web-01', '192.168.1.10'),
            ('srv-web-02', '192.168.1.11'),
            ('srv-web-03', '192.168.1.12'),
        ]
        serveur = None
        for nom, ip in demo_serveurs:
            srv, _ = Serveur.objects.get_or_create(
                adresse_ip=ip,
                defaults={
                    'nom_serveur': nom,
                    'systeme_exploitation': 'Linux',
                    'localisation': 'Datacenter',
                    'statut': 'ACTIF',
                    'date_ajout': timezone.now(),
                },
            )
            if ip == '192.168.1.10':
                serveur = srv

        if LogEntree.objects.exists():
            self.stdout.write(self.style.WARNING('Des logs existent déjà — démo partielle uniquement.'))
            return

        now = timezone.now()
        samples = [
            ('INFO', 'auth_service', 'Connexion réussie'),
            ('WARN', 'api_gateway', 'Requête lente détectée'),
            ('ERROR', 'auth_service', 'Utilisateur inconnu'),
        ]
        logs = []
        for niveau, service, message in samples:
            logs.append(
                LogEntree.objects.create(
                    source=source,
                    serveur=serveur,
                    horodatage=now,
                    niveau=niveau,
                    service=service,
                    message=message,
                    statut_traitement='NOUVEAU',
                    date_insertion=now,
                )
            )

        anomalie = Anomalie.objects.create(
            log=logs[2],
            type_anomalie='auth_failure',
            score=75,
            description='Échecs de connexion répétés',
            date_detection=now,
        )
        Alerte.objects.create(
            anomalie=anomalie,
            severite='MAJEUR',
            canal='SECURITE',
            statut='NOUVEAU',
            date_alerte=now,
        )

        self.stdout.write(self.style.SUCCESS('Données de démo créées (3 logs, 1 anomalie, 1 alerte).'))
