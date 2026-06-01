"""Tests unitaires — import CSV des logs serveur."""
import io

from django.test import TestCase

from logs.import_log_csv import ImportLogCsvError, import_csv_file
from logs.models import ImportLogEntree, ImportLogFichier, Utilisateur

SAMPLE_CSV = """\
Serveur,IP serveur,Date,Heure,IP visiteur,Méthode,URL,Code HTTP
Site témoin,192.168.1.11,31/05/2026,10:00:01,192.168.1.5,GET,/index,200
Site témoin,192.168.1.11,31/05/2026,10:00:02,192.168.1.5,GET,/missing,404
"""


class ImportLogCsvTest(TestCase):
    def setUp(self):
        self.utilisateur = Utilisateur.objects.create(
            nom='Test',
            prenom='Import',
            email='import.test@example.com',
            mot_de_passe='hash',
            role='admin',
        )
        self.utilisateur.set_password('secret')
        self.utilisateur.save()

    def test_import_csv_file_success(self):
        upload = io.BytesIO(SAMPLE_CSV.encode('utf-8'))
        upload.name = 'logs_serveur_site_temoin_2026-05-31.csv'

        fichier = import_csv_file(upload, self.utilisateur)

        self.assertEqual(fichier.lignes_importees, 2)
        self.assertEqual(fichier.lignes_rejetees, 0)
        self.assertEqual(ImportLogFichier.objects.count(), 1)
        self.assertEqual(ImportLogEntree.objects.count(), 2)

        entry = ImportLogEntree.objects.first()
        self.assertEqual(entry.ip_serveur, '192.168.1.11')
        self.assertEqual(entry.code_http, 200)

    def test_import_csv_file_rejects_empty(self):
        upload = io.BytesIO(b'Serveur,IP serveur\n')
        upload.name = 'empty.csv'

        with self.assertRaises(ImportLogCsvError):
            import_csv_file(upload, self.utilisateur)

        self.assertEqual(ImportLogFichier.objects.count(), 0)

    def test_import_csv_file_rejects_missing_columns(self):
        upload = io.BytesIO(b'Date,Heure\n31/05/2026,10:00\n')
        upload.name = 'bad.csv'

        with self.assertRaises(ImportLogCsvError):
            import_csv_file(upload, self.utilisateur)
