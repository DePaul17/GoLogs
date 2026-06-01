"""Export CSV des logs access.log d'un serveur monitoré."""
from __future__ import annotations

import csv
import io
import re
import unicodedata

from django.utils import timezone

from logs.network_probe import resolve_server_name
from logs.services.log_analyzer import (
    fetch_remote_log_content,
    parse_access_log_entries,
)


def slugify_server_name(name: str) -> str:
    normalized = unicodedata.normalize('NFKD', name)
    ascii_name = normalized.encode('ascii', 'ignore').decode('ascii')
    slug = re.sub(r'[^a-zA-Z0-9]+', '_', ascii_name.strip().lower())
    return slug.strip('_') or 'serveur'


def build_server_access_log_csv(host_ip: str) -> tuple[str, str]:
    """Lit access.log et retourne (nom_fichier, contenu_csv)."""
    host_name = resolve_server_name(host_ip)
    content = fetch_remote_log_content(host_ip)
    entries = parse_access_log_entries(content, host_ip, host_name)
    entries.sort(
        key=lambda item: item['datetime'].timestamp() if item.get('datetime') else 0,
        reverse=True,
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        'Serveur',
        'IP serveur',
        'Date',
        'Heure',
        'IP visiteur',
        'Méthode',
        'URL',
        'Code HTTP',
    ])
    for entry in entries:
        writer.writerow([
            host_name,
            host_ip,
            entry['date'],
            entry['time'],
            entry['ip'],
            entry['method'],
            entry['url'],
            entry['status'],
        ])

    report_date = timezone.localdate().strftime('%Y-%m-%d')
    filename = f'logs_serveur_{slugify_server_name(host_name)}_{report_date}.csv'
    return filename, buffer.getvalue()
