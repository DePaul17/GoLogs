"""Tests unitaires — récupération des logs (access.log)."""
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from logs.services.log_analyzer import (
    fetch_filtered_access_logs,
    parse_access_log_entries,
    parse_combined_log_line,
)

SAMPLE_LOG = """\
192.168.1.5 - - [31/May/2026:10:00:01 +0000] "GET /index HTTP/1.1" 200 1234
192.168.1.5 - - [31/May/2026:10:00:02 +0000] "GET /about HTTP/1.1" 200 800
192.168.1.5 - - [31/May/2026:10:00:03 +0000] "GET /missing HTTP/1.1" 404 512
ligne invalide ignorée
"""

SERVER_LOG_CONFIG = {
    '192.168.1.11': {
        'ssh_user': 'test',
        'ssh_password': '',
        'log_file_path': '/var/log/apache2/access.log',
    },
}


class RecuperationLogsTest(SimpleTestCase):
    def test_parse_ligne_access_log_valide(self):
        line = (
            '192.168.1.5 - - [31/May/2026:10:00:01 +0000] '
            '"GET /index HTTP/1.1" 200 1234'
        )
        parsed = parse_combined_log_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['url'], '/index')
        self.assertEqual(parsed['status'], '200')

    def test_parse_ligne_invalide_ignoree(self):
        self.assertIsNone(parse_combined_log_line(''))
        self.assertIsNone(parse_combined_log_line('ceci nest pas un log'))

    def test_parse_contenu_en_entrees_structurees(self):
        entries = parse_access_log_entries(SAMPLE_LOG, '192.168.1.11', 'Site témoin')

        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0]['url'], '/index')
        self.assertEqual(entries[0]['host_ip'], '192.168.1.11')

    @override_settings(SERVER_LOG_CONFIG=SERVER_LOG_CONFIG)
    @patch('logs.services.log_analyzer.fetch_remote_log_content')
    def test_recuperation_logs_depuis_serveur(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_LOG

        display, _, total, error = fetch_filtered_access_logs(
            [('192.168.1.11', 'Site témoin')],
        )

        mock_fetch.assert_called_once_with('192.168.1.11')
        self.assertIsNone(error)
        self.assertEqual(total, 3)
        self.assertEqual(len(display), 3)
