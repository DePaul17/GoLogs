from django.core import mail
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from logs.auth import authenticate_user
from logs.alerting import create_alert, generate_alerts_for_undetected_anomalies
from logs.models import Alerte, Anomalie, LogEntree, Serveur, SourceLog, Utilisateur
from logs.password_reset import (
    make_reset_token,
    parse_reset_token,
    reset_password,
    validate_new_password,
)
from logs.log_search import apply_log_search, parse_search_terms
from logs.utils import parse_log_line


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


class RegistrationTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url = reverse('register')
        self.valid_payload = {
            'nom': 'Martin',
            'prenom': 'Sophie',
            'email': 'sophie.martin@example.com',
            'mot_de_passe': 'MotDePasse2026',
            'mot_de_passe_confirm': 'MotDePasse2026',
        }

    def test_register_page_get(self):
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)

    def test_register_success_redirects_to_login(self):
        response = self.client.post(self.register_url, self.valid_payload)
        self.assertRedirects(response, reverse('login'))
        utilisateur = Utilisateur.objects.get(email='sophie.martin@example.com')
        self.assertEqual(utilisateur.role, 'analyste')
        self.assertTrue(utilisateur.check_password('MotDePasse2026'))

    def test_register_can_login_after_signup(self):
        self.client.post(self.register_url, self.valid_payload)
        login_response = self.client.post(
            reverse('login'),
            {'email': 'sophie.martin@example.com', 'mot_de_passe': 'MotDePasse2026'},
        )
        self.assertRedirects(login_response, reverse('dashboard'))

    def test_register_duplicate_email(self):
        self.client.post(self.register_url, self.valid_payload)
        response = self.client.post(self.register_url, self.valid_payload)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'existe déjà')
        self.assertEqual(
            Utilisateur.objects.filter(email__iexact='sophie.martin@example.com').count(),
            1,
        )

    def test_register_password_mismatch(self):
        payload = {**self.valid_payload, 'mot_de_passe_confirm': 'AutreMotDePasse'}
        response = self.client.post(self.register_url, payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Utilisateur.objects.count(), 0)

    def test_register_redirects_if_already_logged_in(self):
        utilisateur = Utilisateur.objects.create(
            nom='Test',
            prenom='User',
            email='logged@example.com',
            mot_de_passe='',
            role='analyste',
        )
        utilisateur.set_password('MotDePasse2026')
        utilisateur.save()
        session = self.client.session
        session['utilisateur_id'] = utilisateur.id_utilisateur
        session.save()
        response = self.client.get(self.register_url)
        self.assertRedirects(response, reverse('dashboard'))


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


@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class PasswordResetTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.utilisateur = Utilisateur.objects.create(
            nom='Test',
            prenom='Reset',
            email='reset@example.com',
            mot_de_passe='',
            role='admin',
        )
        self.utilisateur.set_password('AncienMotDePasse2026')
        self.utilisateur.save()

    def test_make_and_parse_reset_token(self):
        token = make_reset_token(self.utilisateur.id_utilisateur)
        self.assertEqual(parse_reset_token(token), self.utilisateur.id_utilisateur)

    def test_parse_invalid_token_returns_none(self):
        self.assertIsNone(parse_reset_token('jeton-invalide'))

    def test_validate_new_password_mismatch(self):
        errors = validate_new_password('MotDePasse2026', 'AutreMotDePasse')
        self.assertTrue(errors)

    def test_reset_password_updates_hash(self):
        token = make_reset_token(self.utilisateur.id_utilisateur)
        ok, error = reset_password(
            self.utilisateur.id_utilisateur, token, 'NouveauMotDePasse2026'
        )
        self.assertTrue(ok)
        self.assertIsNone(error)
        self.assertIsNotNone(
            authenticate_user('reset@example.com', 'NouveauMotDePasse2026')
        )
        self.assertIsNone(
            authenticate_user('reset@example.com', 'AncienMotDePasse2026')
        )

    def test_password_reset_request_sends_email(self):
        response = self.client.post(
            reverse('password_reset'),
            {'email': 'reset@example.com'},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('password-reset/confirm', mail.outbox[0].body)

    def test_password_reset_request_unknown_email_no_leak(self):
        response = self.client.post(
            reverse('password_reset'),
            {'email': 'inconnu@example.com'},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 0)

    def test_password_reset_confirm_flow(self):
        token = make_reset_token(self.utilisateur.id_utilisateur)
        url = reverse(
            'password_reset_confirm',
            kwargs={'user_id': self.utilisateur.id_utilisateur, 'token': token},
        )
        response = self.client.post(
            url,
            {
                'mot_de_passe': 'NouveauMotDePasse2026',
                'mot_de_passe_confirm': 'NouveauMotDePasse2026',
            },
        )
        self.assertRedirects(response, reverse('password_reset_complete'))
        self.assertIsNotNone(
            authenticate_user('reset@example.com', 'NouveauMotDePasse2026')
        )


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


class DashboardFilterTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.utilisateur = Utilisateur.objects.create(
            nom='Admin',
            prenom='GoLogs',
            email='admin@gologs.local',
            mot_de_passe='',
            role='admin',
        )
        self.utilisateur.set_password('AdminPass2026')
        self.utilisateur.save()

        self.source_a = SourceLog.objects.create(nom_source='Source A', type_source='app')
        self.source_b = SourceLog.objects.create(nom_source='Source B', type_source='syslog')
        self.serveur_a = Serveur.objects.create(
            nom_serveur='srv-a',
            adresse_ip='10.0.0.10',
        )
        self.serveur_b = Serveur.objects.create(
            nom_serveur='srv-b',
            adresse_ip='10.0.0.11',
        )

        now = timezone.now()
        self.log_error = LogEntree.objects.create(
            source=self.source_a,
            serveur=self.serveur_a,
            horodatage=now,
            niveau='ERROR',
            service='auth_service',
            message='Utilisateur inconnu',
            statut_traitement='NOUVEAU',
            date_insertion=now,
        )
        self.log_info = LogEntree.objects.create(
            source=self.source_b,
            serveur=self.serveur_b,
            horodatage=now,
            niveau='INFO',
            service='api_gateway',
            message='Connexion réussie',
            statut_traitement='NOUVEAU',
            date_insertion=now,
        )
        self.anomalie_auth = Anomalie.objects.create(
            log=self.log_error,
            type_anomalie='auth_failure',
            score=88.0,
            description='Multiples erreurs de connexion',
            date_detection=now,
        )
        self.anomalie_perf = Anomalie.objects.create(
            log=self.log_info,
            type_anomalie='latency_spike',
            score=56.0,
            description='Pic de latence API',
            date_detection=now,
        )
        Alerte.objects.create(
            anomalie=self.anomalie_auth,
            severite='CRITIQUE',
            canal='SECURITE',
            statut='NOUVEAU',
            date_alerte=now,
        )
        Alerte.objects.create(
            anomalie=self.anomalie_perf,
            severite='MAJEUR',
            canal='TABLEAU_DE_BORD',
            statut='EN_COURS',
            date_alerte=now,
        )

        session = self.client.session
        session['utilisateur_id'] = self.utilisateur.id_utilisateur
        session['utilisateur_nom'] = f'{self.utilisateur.prenom} {self.utilisateur.nom}'
        session['utilisateur_role'] = self.utilisateur.role
        session.save()

    def test_dashboard_filters_by_niveau(self):
        response = self.client.get(reverse('dashboard'), {'niveau': 'ERROR'})
        self.assertEqual(response.status_code, 200)
        logs = response.context['derniers_logs']
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].niveau, 'ERROR')

    def test_dashboard_filters_by_search_query(self):
        response = self.client.get(reverse('dashboard'), {'q': 'inconnu'})
        self.assertEqual(response.status_code, 200)
        logs = response.context['derniers_logs']
        self.assertEqual(len(logs), 1)
        self.assertIn('inconnu', logs[0].message.lower())

    def test_dashboard_search_multiple_terms(self):
        response = self.client.get(reverse('dashboard'), {'q': 'ERROR auth'})
        self.assertEqual(response.status_code, 200)
        logs = response.context['derniers_logs']
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].niveau, 'ERROR')
        self.assertEqual(logs[0].service, 'auth_service')

    def test_parse_search_terms_splits_words(self):
        self.assertEqual(parse_search_terms('ERROR, auth inconnu'), ['ERROR', 'auth', 'inconnu'])

    def test_apply_log_search_multiple_terms(self):
        queryset = LogEntree.objects.all()
        results = apply_log_search(queryset, 'INFO api')
        self.assertEqual(results.count(), 1)
        self.assertEqual(results.first().service, 'api_gateway')

    def test_dashboard_filters_alerts_by_severite(self):
        response = self.client.get(reverse('dashboard'), {'alert_severite': 'CRITIQUE'})
        self.assertEqual(response.status_code, 200)
        alertes = response.context['dernieres_alertes']
        self.assertEqual(len(alertes), 1)
        self.assertEqual(alertes[0].severite, 'CRITIQUE')

    def test_dashboard_search_alerts_multiple_terms(self):
        response = self.client.get(reverse('dashboard'), {'alert_q': 'SECURITE auth'})
        self.assertEqual(response.status_code, 200)
        alertes = response.context['dernieres_alertes']
        self.assertEqual(len(alertes), 1)
        self.assertEqual(alertes[0].canal, 'SECURITE')
