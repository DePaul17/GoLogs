"""Préparation des données pour les graphiques du dashboard serveur."""
from __future__ import annotations

CHART_TOP_PAGES_LIMIT = 10
DONUT_COLORS = {
    '200': '#66bb6a',
    '404': '#ffc107',
    '5xx': '#c62828',
}
DONUT_LABELS = {
    '200': '200 OK',
    '404': '404 Not Found',
    '5xx': 'Erreurs serveur (5xx)',
}


def _shorten_url(url: str, max_len: int = 32) -> str:
    if len(url) <= max_len:
        return url
    return url[: max_len - 1] + '…'


def aggregate_status_donut(status_codes: list[dict[str, object]]) -> dict[str, object]:
    """Regroupe les codes HTTP en 200 / 404 / 5xx pour le donut."""
    counts = {'200': 0, '404': 0, '5xx': 0}

    for row in status_codes:
        code = str(row.get('code', ''))
        count = int(row.get('count', 0))
        if code == '200':
            counts['200'] += count
        elif code == '404':
            counts['404'] += count
        elif code.isdigit() and code.startswith('5'):
            counts['5xx'] += count

    labels: list[str] = []
    data: list[int] = []
    colors: list[str] = []

    for key in ('200', '404', '5xx'):
        if counts[key] > 0:
            labels.append(DONUT_LABELS[key])
            data.append(counts[key])
            colors.append(DONUT_COLORS[key])

    total = sum(data)
    return {
        'labels': labels,
        'data': data,
        'colors': colors,
        'total': total,
    }


def build_top_pages_bar(top_pages: list[dict[str, object]]) -> dict[str, object]:
    """Données bar chart — pages les plus visitées."""
    rows = top_pages[:CHART_TOP_PAGES_LIMIT]
    return {
        'labels': [_shorten_url(str(row['url'])) for row in rows],
        'full_labels': [str(row['url']) for row in rows],
        'data': [int(row['hits']) for row in rows],
    }


def build_chart_payload(stats: dict[str, object]) -> dict[str, object]:
    """Payload JSON-serialisable pour Chart.js."""
    return {
        'top_pages': build_top_pages_bar(list(stats.get('top_pages', []))),
        'status_donut': aggregate_status_donut(list(stats.get('status_codes', []))),
    }
