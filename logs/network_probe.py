"""Sonde réseau passive pour détecter les serveurs monitorés en marche."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings

from logs.models import Serveur


def resolve_server_name(ip: str, fallback: str | None = None) -> str:
    """Nom affiché d'un serveur monitoré (settings → BDD → IP)."""
    known = getattr(settings, 'MONITORED_SERVER_NAMES', {}).get(ip)
    if known:
        return known
    if fallback:
        return fallback
    return ip


def ping_ip(ip: str, port: int = 22, timeout: float = 2.0) -> bool:
    """Vérifie si une IP répond sur un port TCP (SSH 22 par défaut)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def list_running_monitored_servers() -> list[dict]:
    """
    Sonde les IP configurées en parallèle et retourne celles joignables.
    Chaque entrée : {ip, nom, serveur (ORM ou None), label}.
    """
    ips = getattr(
        settings,
        'MONITORED_SERVER_IPS',
        ['192.168.1.10', '192.168.1.11', '192.168.1.12'],
    )
    port = int(getattr(settings, 'NETWORK_PROBE_SSH_PORT', 22))
    timeout = float(getattr(settings, 'NETWORK_PROBE_TIMEOUT_SEC', 1.2))
    parallelism = int(getattr(settings, 'NETWORK_PROBE_PARALLELISM', 8))

    if not ips:
        return []

    db_by_ip = {
        s.adresse_ip: s
        for s in Serveur.objects.filter(adresse_ip__in=ips)
    }

    worker_count = max(1, min(parallelism, len(ips)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        reachable_flags = list(
            executor.map(lambda ip_: ping_ip(ip_, port, timeout), ips),
        )

    running: list[dict] = []
    for ip, reachable in zip(ips, reachable_flags):
        if not reachable:
            continue
        serveur = db_by_ip.get(ip)
        nom = resolve_server_name(
            ip,
            serveur.nom_serveur if serveur else None,
        )
        running.append({
            'ip': ip,
            'nom': nom,
            'serveur': serveur,
            'label': f'{nom} ({ip})',
        })
    return running
