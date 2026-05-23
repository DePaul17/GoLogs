from django.test import TestCase
from django.utils import timezone
from logs.utils import parse_log_line
from logs.models import SourceLog, Serveur, LogEntree, Anomalie, Alerte
from logs.alerting import create_alert, generate_alerts_for_undetected_anomalies


class LogUtilsTest(TestCase):
    def test_parse_iso_log_line(self):
        line = '2024-05-23T10:12:34 ERROR auth_service Utilisateur inconnu'
        parsed = parse_log_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['niveau'], 'ERROR')
        self.assertEqual(parsed['service'], 'auth_service')
        self.assertEqual(parsed['message'], 'Utilisateur inconnu')
        self.assertEqual(parsed['horodatage'].year, 2024)
        self.assertEqual(parsed['horodatage'].month, 5)
        self.assertEqual(parsed['horodatage'].day, 23)

    def test_parse_space_separated_timestamp(self):
        line = '2024-05-23 10:12:34 WARN api_gateway Requête lente détectée'
        parsed = parse_log_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['niveau'], 'WARN')
        self.assertEqual(parsed['service'], 'api_gateway')
        self.assertEqual(parsed['message'], 'Requête lente détectée')
        self.assertEqual(parsed['horodatage'].hour, 10)
        self.assertEqual(parsed['horodatage'].minute, 12)

    def test_parse_invalid_line_returns_none(self):
        parsed = parse_log_line('')
        self.assertIsNone(parsed)

    def test_parse_fallback_line(self):
        line = '2024-05-23 10:12:34 INFO backup_service Sauvegarde terminée'
        parsed = parse_log_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['niveau'], 'INFO')
        self.assertEqual(parsed['service'], 'backup_service')
        self.assertEqual(parsed['message'], 'Sauvegarde terminée')


class AlertingTest(TestCase):
    def setUp(self):
        self.source = SourceLog.objects.create(nom_source='Source A', type_source='syslog')
        self.serveur = Serveur.objects.create(nom_serveur='Server1', adresse_ip='192.168.1.1')

    def test_create_alert_for_anomalie(self):
        log = LogEntree.objects.create(
            source=self.source,
            serveur=self.serveur,
            horodatage=timezone.now(),
            niveau='ERROR',
            service='auth',
            message='Échec de connexion',
            statut_traitement='NOUVEAU',
            date_insertion=timezone.now(),
        )
        anomalie = Anomalie.objects.create(
            log=log,
            type_anomalie='Erreur critique',
            score=90.0,
            description='Mot de passe invalide',
            date_detection=timezone.now(),
        )

        alert = create_alert(anomalie)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.severite, 'CRITIQUE')
        self.assertEqual(alert.canal, 'TABLEAU_DE_BORD')
        self.assertEqual(alert.statut, 'NOUVEAU')
        self.assertEqual(alert.anomalie, anomalie)

    def test_generate_alerts_for_undetected_anomalies(self):
        log = LogEntree.objects.create(
            source=self.source,
            serveur=self.serveur,
            horodatage=timezone.now(),
            niveau='WARN',
            service='api',
            message='Temps de réponse élevé',
            statut_traitement='NOUVEAU',
            date_insertion=timezone.now(),
        )
        anomalie = Anomalie.objects.create(
            log=log,
            type_anomalie='Alerte de performance',
            score=55.0,
            description='Dégradation CPU',
            date_detection=timezone.now(),
        )

        alerts = generate_alerts_for_undetected_anomalies()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severite, 'MAJEUR')
        self.assertEqual(Alerte.objects.filter(anomalie=anomalie).count(), 1)

    def test_generate_alerts_skips_existing(self):
        log = LogEntree.objects.create(
            source=self.source,
            serveur=self.serveur,
            horodatage=timezone.now(),
            niveau='ERROR',
            service='db',
            message='Base non disponible',
            statut_traitement='NOUVEAU',
            date_insertion=timezone.now(),
        )
        anomalie = Anomalie.objects.create(
            log=log,
            type_anomalie='Erreur critique',
            score=95.0,
            description='Erreur de base de données',
            date_detection=timezone.now(),
        )
        create_alert(anomalie)

        alerts = generate_alerts_for_undetected_anomalies()

        self.assertEqual(len(alerts), 0)
        self.assertEqual(Alerte.objects.filter(anomalie=anomalie).count(), 1)
