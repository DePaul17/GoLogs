# Generated manually for import de logs CSV

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('logs', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ImportLogFichier',
            fields=[
                ('id_fichier', models.AutoField(primary_key=True, serialize=False)),
                ('nom_fichier', models.CharField(max_length=255)),
                ('date_import', models.DateTimeField(auto_now_add=True)),
                ('lignes_importees', models.PositiveIntegerField(default=0)),
                ('lignes_rejetees', models.PositiveIntegerField(default=0)),
                ('utilisateur', models.ForeignKey(
                    db_column='ID_UTILISATEUR',
                    on_delete=django.db.models.deletion.CASCADE,
                    to='logs.utilisateur',
                )),
            ],
            options={
                'verbose_name': 'Fichier de logs importé',
                'verbose_name_plural': 'Fichiers de logs importés',
                'db_table': 'IMPORT_LOG_FICHIER',
                'ordering': ['-date_import'],
            },
        ),
        migrations.CreateModel(
            name='ImportLogEntree',
            fields=[
                ('id_entree', models.AutoField(primary_key=True, serialize=False)),
                ('nom_serveur', models.CharField(max_length=100)),
                ('ip_serveur', models.CharField(max_length=45)),
                ('date_log', models.CharField(max_length=20)),
                ('heure_log', models.CharField(max_length=20)),
                ('ip_visiteur', models.CharField(max_length=45)),
                ('methode', models.CharField(max_length=10)),
                ('url', models.CharField(max_length=512)),
                ('code_http', models.IntegerField(blank=True, null=True)),
                ('fichier', models.ForeignKey(
                    db_column='ID_FICHIER',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='entrees',
                    to='logs.importlogfichier',
                )),
            ],
            options={
                'verbose_name': 'Entrée de log importée',
                'verbose_name_plural': 'Entrées de logs importées',
                'db_table': 'IMPORT_LOG_ENTREE',
                'ordering': ['-id_entree'],
            },
        ),
    ]
