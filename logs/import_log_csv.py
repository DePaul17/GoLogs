"""Import de fichiers CSV exportés depuis GoLogs (access.log)."""
from __future__ import annotations

import csv
import io
from typing import BinaryIO

from logs.models import ImportLogEntree, ImportLogFichier, Utilisateur

CSV_COLUMNS = {
    'serveur': ('serveur', 'server'),
    'ip_serveur': ('ip serveur', 'server ip', 'ip_serveur'),
    'date': ('date',),
    'heure': ('heure', 'time'),
    'ip_visiteur': ('ip visiteur', 'client ip', 'ip_visiteur', 'ip client'),
    'methode': ('méthode', 'methode', 'method'),
    'url': ('url',),
    'code_http': ('code http', 'code_http', 'status', 'code'),
}


class ImportLogCsvError(ValueError):
    """Fichier CSV invalide ou illisible."""


def _normalize_header(value: str) -> str:
    return value.strip().lower().replace('_', ' ')


def _map_headers(fieldnames: list[str] | None) -> dict[str, str]:
    if not fieldnames:
        raise ImportLogCsvError('Le fichier CSV est vide ou sans en-tête.')

    mapping: dict[str, str] = {}
    normalized = {_normalize_header(name): name for name in fieldnames if name}

    for target, aliases in CSV_COLUMNS.items():
        for alias in aliases:
            source = normalized.get(alias)
            if source:
                mapping[target] = source
                break

    required = ('ip_serveur', 'date', 'heure', 'ip_visiteur', 'url', 'code_http')
    missing = [key for key in required if key not in mapping]
    if missing:
        raise ImportLogCsvError(
            'Colonnes CSV manquantes. Attendu : Serveur, IP serveur, Date, Heure, '
            'IP visiteur, Méthode, URL, Code HTTP.',
        )
    return mapping


def _parse_code_http(raw: str) -> int | None:
    value = (raw or '').strip()
    if not value or value == '-':
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _read_row(row: dict[str, str], mapping: dict[str, str]) -> dict[str, object] | None:
    def cell(key: str, default: str = '') -> str:
        source = mapping.get(key)
        if not source:
            return default
        return (row.get(source) or '').strip()

    ip_serveur = cell('ip_serveur')
    if not ip_serveur:
        return None

    return {
        'nom_serveur': cell('serveur') or ip_serveur,
        'ip_serveur': ip_serveur,
        'date_log': cell('date') or '—',
        'heure_log': cell('heure') or '—',
        'ip_visiteur': cell('ip_visiteur') or '—',
        'methode': cell('methode') or '—',
        'url': cell('url') or '—',
        'code_http': _parse_code_http(cell('code_http')),
    }


def import_csv_file(
    uploaded_file: BinaryIO,
    utilisateur: Utilisateur,
    filename: str = '',
) -> ImportLogFichier:
    raw = uploaded_file.read()
    if isinstance(raw, bytes):
        text = raw.decode('utf-8-sig', errors='replace')
    else:
        text = str(raw)

    if not text.strip():
        raise ImportLogCsvError('Le fichier CSV est vide.')

    reader = csv.DictReader(io.StringIO(text))
    mapping = _map_headers(reader.fieldnames)

    fichier = ImportLogFichier.objects.create(
        utilisateur=utilisateur,
        nom_fichier=filename or getattr(uploaded_file, 'name', 'import.csv'),
    )

    entries: list[ImportLogEntree] = []
    rejected = 0

    for row in reader:
        parsed = _read_row(row, mapping)
        if parsed is None:
            rejected += 1
            continue
        entries.append(
            ImportLogEntree(
                fichier=fichier,
                **parsed,
            ),
        )

    if not entries:
        fichier.delete()
        raise ImportLogCsvError(
            'Aucune ligne valide trouvée dans le CSV.',
        )

    ImportLogEntree.objects.bulk_create(entries, batch_size=500)
    fichier.lignes_importees = len(entries)
    fichier.lignes_rejetees = rejected
    fichier.save(update_fields=['lignes_importees', 'lignes_rejetees'])
    return fichier
