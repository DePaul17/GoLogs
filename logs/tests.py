from django.test import TestCase
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
