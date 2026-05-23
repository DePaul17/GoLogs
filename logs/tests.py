from django.test import TestCase
from django.utils import timezone
from logs.utils import parse_log_line
from logs.models import SourceLog, Serveur, LogEntree, Anomalie, Alerte, Utilisateur
from logs.alerting import create_alert, generate_alerts_for_undetected_anomalies
from logs.auth import authenticate_user


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


class AuthTest(TestCase):
    def test_authenticate_user_success(self):
        utilisateur = Utilisateur.objects.create(
            nom='Diallo',
            prenom='Aramata',
            email='aramata@example.com',
            mot_de_passe='',
            role='admin',
        )
        utilisateur.set_password('MotDePasse2026')
        utilisateur.save()

        authenticated = authenticate_user('aramata@example.com', 'MotDePasse2026')

        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.email, 'aramata@example.com')

    def test_authenticate_user_wrong_password(self):
        utilisateur = Utilisateur.objects.create(
            nom='Diallo',
            prenom='Aramata',
            email='aramata@example.com',
            mot_de_passe='',
            role='admin',
        )
        utilisateur.set_password('MotDePasse2026')
        utilisateur.save()

        authenticated = authenticate_user('aramata@example.com', 'MauvaisMotDePasse')

        self.assertIsNone(authenticated)

    def test_authenticate_user_unknown_email(self):
        authenticated = authenticate_user('inconnu@example.com', 'MotDePasse2026')
        self.assertIsNone(authenticated)


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


class AlertProcessingTest(TestCase):
    def setUp(self):
        self.source = SourceLog.objects.create(nom_source='Source B', type_source='syslog')
        self.serveur = Serveur.objects.create(nom_serveur='Server2', adresse_ip='192.168.1.2')
        self.log = LogEntree.objects.create(
            source=self.source,
            serveur=self.serveur,
            horodatage=timezone.now(),
            niveau='ERROR',
            service='db',
            message='Problème base',
            statut_traitement='NOUVEAU',
            date_insertion=timezone.now(),
        )
        self.anomalie = Anomalie.objects.create(
            log=self.log,
            type_anomalie='Erreur critique',
            score=90.0,
            description='Base indisponible',
            date_detection=timezone.now(),
        )
        self.alert = Alerte.objects.create(
            anomalie=self.anomalie,
            severite='CRITIQUE',
            canal='TABLEAU_DE_BORD',
            statut='NOUVEAU',
            date_alerte=timezone.now(),
        )

    def test_update_alert_status(self):
        from logs.alerting import update_alert_status

        updated = update_alert_status(self.alert.id_alerte, 'EN_COURS')

        self.assertEqual(updated.statut, 'EN_COURS')
        self.assertEqual(Alerte.objects.get(id_alerte=self.alert.id_alerte).statut, 'EN_COURS')

    def test_update_alert_status_invalid_id(self):
        from logs.alerting import update_alert_status

        with self.assertRaises(ValueError):
            update_alert_status(999999, 'RESOLU')


class ReportGenerationTest(TestCase):
    def setUp(self):
        self.user = Utilisateur.objects.create(
            nom='Test',
            prenom='User',
            email='test@example.com',
            mot_de_passe='',
            role='analyste',
        )
        self.user.set_password('pass')
        self.user.save()
        self.source = SourceLog.objects.create(nom_source='Source C', type_source='app')
        self.serveur = Serveur.objects.create(nom_serveur='Server3', adresse_ip='192.168.1.3')

    def test_generate_report_creates_rapport(self):
        from logs.reports import generate_report
        from datetime import date

        LogEntree.objects.create(
            source=self.source,
            serveur=self.serveur,
            horodatage=timezone.now(),
            niveau='INFO',
            service='web',
            message='Requête traitée',
            statut_traitement='TRAITE',
            date_insertion=timezone.now(),
        )

        rapport = generate_report(date.today(), date.today(), utilisateur=self.user, output_dir='.')

        self.assertIsNotNone(rapport)
        self.assertEqual(rapport.utilisateur, self.user)
        self.assertTrue(rapport.chemin_fichier.endswith('.csv'))
        self.assertEqual(rapport.date_debut, date.today())
        self.assertEqual(rapport.date_fin, date.today())
