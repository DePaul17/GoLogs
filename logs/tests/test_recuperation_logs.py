"""Tests unitaires — récupération des logs et comptage des pages visitées."""
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from logs.services.log_analyzer import (
    analyze_access_log,
    fetch_filtered_access_logs,
    filter_access_entries,
    parse_access_log_entries,
    parse_combined_log_line,
)

SAMPLE_LOG = """\
192.168.1.5 - - [31/May/2026:10:00:01 +0000] "GET /index HTTP/1.1" 200 1234
192.168.1.5 - - [31/May/2026:10:00:02 +0000] "GET /about HTTP/1.1" 200 800
192.168.1.5 - - [31/May/2026:10:00:03 +0000] "GET /index HTTP/1.1" 200 1234
192.168.1.5 - - [31/May/2026:10:00:04 +0000] "GET /missing HTTP/1.1" 404 512
192.168.1.6 - - [31/May/2026:10:00:05 +0000] "GET /contact HTTP/1.1" 200 600
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
    """Récupération et parsing des lignes access.log (Combined Log Format)."""

    def test_parse_ligne_access_log_valide(self):
        line = (
            '192.168.1.5 - - [31/May/2026:10:00:01 +0000] '
            '"GET /index HTTP/1.1" 200 1234'
        )
        parsed = parse_combined_log_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['ip'], '192.168.1.5')
        self.assertEqual(parsed['method'], 'GET')
        self.assertEqual(parsed['url'], '/index')
        self.assertEqual(parsed['status'], '200')

    def test_parse_ligne_invalide_ignoree(self):
        self.assertIsNone(parse_combined_log_line(''))
        self.assertIsNone(parse_combined_log_line('ceci nest pas un log'))

    def test_parse_contenu_en_entrees_structurees(self):
        entries = parse_access_log_entries(SAMPLE_LOG, '192.168.1.11', 'Site témoin')

        self.assertEqual(len(entries), 5)
        self.assertEqual(entries[0]['url'], '/index')
        self.assertEqual(entries[0]['host_ip'], '192.168.1.11')
        self.assertEqual(entries[0]['host_name'], 'Site témoin')
        self.assertEqual(entries[0]['status'], '200')

    @override_settings(SERVER_LOG_CONFIG=SERVER_LOG_CONFIG)
    @patch('logs.services.log_analyzer.fetch_remote_log_content')
    def test_recuperation_logs_depuis_serveur(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_LOG

        display, top_pages, total, error = fetch_filtered_access_logs(
            [('192.168.1.11', 'Site témoin')],
        )

        mock_fetch.assert_called_once_with('192.168.1.11')
        self.assertIsNone(error)
        self.assertEqual(total, 5)
        self.assertEqual(len(display), 5)
        self.assertEqual(display[0]['url'], '/contact')
        self.assertEqual(len(top_pages), 4)


class ComptagePagesVisiteesTest(SimpleTestCase):
    """Comptage et classement des pages les plus visitées."""

    def test_compte_visites_par_url(self):
        stats = analyze_access_log(SAMPLE_LOG)

        self.assertEqual(stats['total_requests'], 5)
        self.assertEqual(stats['unique_pages'], 4)
        self.assertEqual(stats['top_pages'][0]['url'], '/index')
        self.assertEqual(stats['top_pages'][0]['hits'], 2)

    def test_classement_pages_par_nombre_de_visites(self):
        stats = analyze_access_log(SAMPLE_LOG)
        pages = {row['url']: row['hits'] for row in stats['top_pages']}

        self.assertEqual(pages['/index'], 2)
        self.assertEqual(pages['/about'], 1)
        self.assertEqual(pages['/contact'], 1)
        self.assertEqual(pages['/missing'], 1)

    def test_comptage_pages_apres_filtre_mot_cle(self):
        entries = parse_access_log_entries(SAMPLE_LOG, '192.168.1.11', 'Site témoin')
        _, top_pages, total = filter_access_entries(entries, keyword='index')

        self.assertEqual(total, 2)
        self.assertEqual(len(top_pages), 1)
        self.assertEqual(top_pages[0]['url'], '/index')
        self.assertEqual(top_pages[0]['hits'], 2)

    @override_settings(SERVER_LOG_CONFIG=SERVER_LOG_CONFIG)
    @patch('logs.services.log_analyzer.fetch_remote_log_content')
    def test_top_pages_apres_recuperation_logs(self, mock_fetch):
        mock_fetch.return_value = SAMPLE_LOG

        _, top_pages, total, error = fetch_filtered_access_logs(
            [('192.168.1.11', 'Site témoin')],
        )

        self.assertIsNone(error)
        self.assertEqual(total, 5)
        self.assertEqual(top_pages[0]['url'], '/index')
        self.assertEqual(top_pages[0]['hits'], 2)
