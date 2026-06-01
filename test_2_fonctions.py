#!/usr/bin/env python3
"""
2 tests rapides — sans manage.py, sans base de données.

Usage :
    cd ~/GoLogs
    source venv/bin/activate
    pip install Django
    python test_2_fonctions.py
"""
from __future__ import annotations

import os
import sys

# Django minimal (juste pour importer logs.services.log_analyzer)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gologs.settings')

try:
    import django
    django.setup()
except ImportError:
    print('ERREUR : Django manquant. Lance : pip install Django')
    sys.exit(1)

from logs.services.log_analyzer import analyze_access_log, parse_access_log_entries

LOG_EXEMPLE = """\
192.168.1.5 - - [31/May/2026:10:00:01 +0000] "GET /index HTTP/1.1" 200 1234
192.168.1.5 - - [31/May/2026:10:00:02 +0000] "GET /about HTTP/1.1" 200 800
192.168.1.5 - - [31/May/2026:10:00:03 +0000] "GET /index HTTP/1.1" 200 1234
192.168.1.5 - - [31/May/2026:10:00:04 +0000] "GET /missing HTTP/1.1" 404 512
"""


def test_recuperation_logs() -> None:
    """Test 1 — lire et structurer les lignes du access.log."""
    entrees = parse_access_log_entries(LOG_EXEMPLE, '192.168.1.11', 'Site témoin')
    assert len(entrees) == 4, f'4 lignes attendues, {len(entrees)} reçues'
    assert entrees[0]['url'] == '/index'
    assert entrees[0]['status'] == '200'
    print('OK  Test 1 — récupération des logs')


def test_comptage_pages() -> None:
    """Test 2 — compter les pages les plus visitées."""
    stats = analyze_access_log(LOG_EXEMPLE)
    top = stats['top_pages'][0]
    assert top['url'] == '/index', f'/index attendu, {top["url"]} reçu'
    assert top['hits'] == 2, f'2 visites attendues, {top["hits"]} reçues'
    print('OK  Test 2 — comptage des pages visitées')


def main() -> int:
    tests = [test_recuperation_logs, test_comptage_pages]
    ok = 0
    for test in tests:
        try:
            test()
            ok += 1
        except AssertionError as exc:
            print(f'ECHEC  {test.__doc__ or test.__name__} → {exc}')
        except Exception as exc:
            print(f'ERREUR  {test.__name__} → {exc}')

    print(f'\n{ok}/{len(tests)} tests réussis')
    return 0 if ok == len(tests) else 1


if __name__ == '__main__':
    sys.exit(main())
