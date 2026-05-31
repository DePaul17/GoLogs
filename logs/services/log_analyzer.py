"""Lecture et analyse des logs Apache/Nginx (Combined Log Format) via SSH."""
from __future__ import annotations

import re
import shlex
from collections import Counter

import paramiko
from django.conf import settings

COMBINED_LOG_RE = re.compile(
    r'^'
    r'(?P<ip>\S+) '
    r'\S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) '
    r'(?P<bytes>\S+)'
)

TOP_LIMIT = 20


class LogAnalyzerError(RuntimeError):
    """Impossible de lire ou d'analyser le fichier de log distant."""


def _ssh_connect_kwargs() -> dict[str, object]:
    hostname = getattr(settings, 'LOG_HOST_IP', '').strip()
    username = getattr(settings, 'LOG_HOST_USER', '').strip()
    password = getattr(settings, 'LOG_HOST_PASSWORD', '')

    if not hostname:
        raise LogAnalyzerError('Configurer LOG_HOST_IP dans settings.py.')
    if not username:
        raise LogAnalyzerError('Configurer LOG_HOST_USER dans settings.py.')
    if password == '':
        raise LogAnalyzerError('Configurer LOG_HOST_PASSWORD dans settings.py.')

    return {
        'hostname': hostname,
        'port': int(getattr(settings, 'LOG_HOST_SSH_PORT', 22)),
        'username': username,
        'password': password,
        'timeout': int(getattr(settings, 'LOG_SSH_CONNECT_TIMEOUT_SEC', 15)),
        'allow_agent': False,
        'look_for_keys': False,
        'banner_timeout': int(getattr(settings, 'LOG_SSH_CONNECT_TIMEOUT_SEC', 15)),
    }


def fetch_remote_log_content(log_path: str | None = None) -> str:
    """Récupère le contenu du fichier de log via SSH."""
    path = log_path or getattr(settings, 'LOG_FILE_PATH', '/var/log/apache2/access.log')
    kw = _ssh_connect_kwargs()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(**kw)
        _, stdout, stderr = client.exec_command(f'cat {shlex.quote(path)}')
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace').strip()
        if exit_code != 0:
            raise LogAnalyzerError(
                err or out.strip() or f'Impossible de lire {path} sur {kw["hostname"]}.',
            )
        return out
    except LogAnalyzerError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LogAnalyzerError(
            f'Connexion SSH vers {kw.get("hostname")} impossible : {exc}',
        ) from exc
    finally:
        client.close()


def parse_combined_log_line(line: str) -> dict[str, str] | None:
    """Parse une ligne Combined Log Format ; retourne None si non reconnue."""
    line = line.strip()
    if not line:
        return None
    match = COMBINED_LOG_RE.match(line)
    if not match:
        return None
    return match.groupdict()


def analyze_access_log(content: str) -> dict[str, object]:
    """Agrège les statistiques à partir du contenu brut du access.log."""
    page_hits: Counter[str] = Counter()
    errors_404: Counter[str] = Counter()
    status_codes: Counter[str] = Counter()
    ip_hits: Counter[str] = Counter()
    lines_parsed = 0
    lines_skipped = 0

    for line in content.splitlines():
        parsed = parse_combined_log_line(line)
        if parsed is None:
            lines_skipped += 1
            continue

        lines_parsed += 1
        url = parsed['url']
        status = parsed['status']
        ip = parsed['ip']

        page_hits[url] += 1
        status_codes[status] += 1
        ip_hits[ip] += 1
        if status == '404':
            errors_404[url] += 1

    total_requests = lines_parsed

    top_pages = [{'url': url, 'hits': hits} for url, hits in page_hits.most_common(TOP_LIMIT)]
    top_404 = [{'url': url, 'count': count} for url, count in errors_404.most_common(TOP_LIMIT)]
    top_ips = [{'ip': ip, 'hits': hits} for ip, hits in ip_hits.most_common(TOP_LIMIT)]

    status_breakdown = []
    for code, count in sorted(status_codes.items(), key=lambda item: (-item[1], item[0])):
        percent = round((count / total_requests) * 100, 1) if total_requests else 0.0
        status_breakdown.append({
            'code': code,
            'count': count,
            'percent': percent,
        })

    return {
        'total_requests': total_requests,
        'top_pages': top_pages,
        'errors_404': top_404,
        'status_codes': status_breakdown,
        'top_ips': top_ips,
        'lines_parsed': lines_parsed,
        'lines_skipped': lines_skipped,
    }


def get_log_statistics(log_path: str | None = None) -> dict[str, object]:
    """Point d'entrée : SSH + analyse du access.log distant."""
    path = log_path or getattr(settings, 'LOG_FILE_PATH', '/var/log/apache2/access.log')
    host = getattr(settings, 'LOG_HOST_IP', '')
    content = fetch_remote_log_content(path)
    stats = analyze_access_log(content)
    stats['log_file'] = path
    stats['host'] = host
    return stats
