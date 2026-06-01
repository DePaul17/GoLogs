#!/usr/bin/env python3
"""
Test rapide — récupération des logs uniquement (sans report, sans manage.py).

Usage :
    cd ~/GoLogs
    source venv/bin/activate
    pip install Django
    python test_2_fonctions.py
"""
from __future__ import annotations

import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gologs.settings')

try:
    import django
    django.setup()
except ImportError:
    print('ERREUR : Django manquant. Lance : pip install Django')
    sys.exit(1)

from logs.services.log_analyzer import parse_access_log_entries, parse_combined_log_line

LOG_EXEMPLE = """\
192.168.1.5 - - [31/May/2026:10:00:01 +0000] "GET /index HTTP/1.1" 200 1234
192.168.1.5 - - [31/May/2026:10:00:02 +0000] "GET /about HTTP/1.1" 200 800
192.168.1.5 - - [31/May/2026:10:00:03 +0000] "GET /missing HTTP/1.1" 404 512
ligne invalide ignorée
"""


def test_parse_ligne_log() -> None:
    line = (
        '192.168.1.5 - - [31/May/2026:10:00:01 +0000] '
        '"GET /index HTTP/1.1" 200 1234'
    )
    parsed = parse_combined_log_line(line)
    assert parsed is not None
    assert parsed['url'] == '/index'
    assert parsed['status'] == '200'
    print('OK  Parse une ligne access.log')


def test_recuperation_logs() -> None:
    entrees = parse_access_log_entries(LOG_EXEMPLE, '192.168.1.11', 'Site témoin')
    assert len(entrees) == 3, f'3 lignes attendues, {len(entrees)} reçues'
    assert entrees[0]['url'] == '/index'
    assert entrees[0]['host_ip'] == '192.168.1.11'
    print('OK  Récupération des logs (contenu → entrées structurées)')


def main() -> int:
    tests = [test_parse_ligne_log, test_recuperation_logs]
    ok = 0
    for test in tests:
        try:
            test()
            ok += 1
        except AssertionError as exc:
            print(f'ECHEC  {test.__name__} → {exc}')
        except Exception as exc:
            print(f'ERREUR  {test.__name__} → {exc}')

    print(f'\n{ok}/{len(tests)} tests réussis')
    return 0 if ok == len(tests) else 1


if __name__ == '__main__':
    sys.exit(main())
