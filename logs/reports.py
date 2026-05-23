"""Module de génération de rapports au format CSV basés sur les logs, anomalies et alertes."""

import csv
from pathlib import Path
from django.utils import timezone
from logs.models import Rapport, LogEntree, Anomalie, Alerte


def generate_report(start_date, end_date, utilisateur, output_dir=None, type_rapport='Synthèse des logs'):
    logs = LogEntree.objects.filter(horodatage__date__gte=start_date, horodatage__date__lte=end_date)
    anomalies = Anomalie.objects.filter(date_detection__date__gte=start_date, date_detection__date__lte=end_date)
    alerts = Alerte.objects.filter(date_alerte__date__gte=start_date, date_alerte__date__lte=end_date)

    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
    else:
        output_path = Path('.')

    file_name = f'report_{start_date}_{end_date}.csv'
    file_path = output_path / file_name

    with file_path.open('w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Type de rapport', type_rapport])
        writer.writerow(['Période', f'{start_date} à {end_date}'])
        writer.writerow(['Logs importés', logs.count()])
        writer.writerow(['Anomalies détectées', anomalies.count()])
        writer.writerow(['Alertes générées', alerts.count()])
        writer.writerow([])
        writer.writerow(['Logs détaillés'])
        writer.writerow(['ID', 'Source', 'Serveur', 'Horodatage', 'Niveau', 'Service', 'Message'])
        for log in logs.order_by('horodatage')[:200]:
            writer.writerow([
                log.id_log,
                log.source.nom_source,
                log.serveur.nom_serveur,
                log.horodatage,
                log.niveau,
                log.service,
                log.message,
            ])

    rapport = Rapport.objects.create(
        utilisateur=utilisateur,
        type_rapport=type_rapport,
        date_debut=start_date,
        date_fin=end_date,
        chemin_fichier=str(file_path),
        date_generation=timezone.now(),
    )

    return rapport
