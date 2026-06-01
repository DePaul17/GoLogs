"""Tests unitaires — export CSV access.log."""
from django.test import SimpleTestCase

from logs.access_log_csv import slugify_server_name


class AccessLogCsvTest(SimpleTestCase):
    def test_slugify_server_name(self):
        self.assertEqual(slugify_server_name('Site témoin'), 'site_temoin')
        self.assertEqual(slugify_server_name('MariaDB'), 'mariadb')
        self.assertEqual(slugify_server_name('   '), 'serveur')
