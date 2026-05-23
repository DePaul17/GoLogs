import re
from datetime import datetime


LOG_LINE_REGEX = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)(?:\s+|,)\s*(?P<level>[A-Za-z]+)\s+(?P<service>[^\s]+)\s+(?P<message>.+)")


def parse_log_line(line):
    """Tentative de parsing d'une ligne de log en champ normalisés.

    Champs retournés : horodatage (datetime), niveau, service, message
    Si le parsing échoue, retourne None.
    """
    line = line.strip()
    if not line:
        return None

    m = LOG_LINE_REGEX.match(line)
    if m:
        ts = m.group('timestamp')
        try:
            # accepte ISO ou espace séparateur
            ts_parsed = datetime.fromisoformat(ts.replace(' ', 'T'))
        except Exception:
            try:
                ts_parsed = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
            except Exception:
                ts_parsed = None

        return {
            'horodatage': ts_parsed,
            'niveau': m.group('level'),
            'service': m.group('service'),
            'message': m.group('message'),
        }

    # Fallback simple: timestamp au début, reste du message
    parts = line.split(' ', 3)
    if len(parts) >= 3:
        maybe_ts = parts[0]
        try:
            ts_parsed = datetime.fromisoformat(maybe_ts.replace(' ', 'T'))
        except Exception:
            ts_parsed = None

        return {
            'horodatage': ts_parsed,
            'niveau': parts[1] if len(parts) > 1 else 'INFO',
            'service': parts[2] if len(parts) > 2 else '',
            'message': parts[3] if len(parts) > 3 else ' '.join(parts[3:]) if len(parts) > 3 else line,
        }

    return None
