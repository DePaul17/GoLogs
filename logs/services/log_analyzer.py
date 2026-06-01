"""Lecture et analyse des logs Apache/Nginx (Combined Log Format) via SSH."""
from __future__ import annotations

import re
import shlex
import subprocess
from collections import Counter, deque
from datetime import date, datetime
from pathlib import Path

import paramiko
from django.conf import settings

COMBINED_LOG_RE = re.compile(
    r'^'
    r'(?P<ip>\S+) '
    r'\S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}|-) '
    r'(?P<bytes>\S+)'
    r'(?: .*)?$',
)

TOP_LIMIT = 20
RECENT_LIMIT = 50
FILTER_LIMIT = 100
DEFAULT_LOG_CANDIDATES = (
    '/var/log/apache2/access.log',
    '/var/log/apache2/other_vhosts_access.log',
    '/var/log/nginx/access.log',
    '/var/log/httpd/access_log',
)

_resolved_log_paths: dict[str, str] = {}


class LogAnalyzerError(RuntimeError):
    """Impossible de lire ou d'analyser le fichier de log distant."""


def get_server_log_config(host_ip: str) -> dict[str, str] | None:
    """Configuration SSH/log pour une IP monitorée, ou None si non configurée."""
    configs = getattr(settings, 'SERVER_LOG_CONFIG', {})
    config = configs.get(host_ip)
    if config:
        return config

    legacy_ip = getattr(settings, 'LOG_HOST_IP', '').strip()
    if host_ip == legacy_ip and legacy_ip:
        return {
            'ssh_user': getattr(settings, 'LOG_HOST_USER', ''),
            'ssh_password': getattr(settings, 'LOG_HOST_PASSWORD', ''),
            'log_file_path': getattr(settings, 'LOG_FILE_PATH', '/var/log/apache2/access.log'),
        }
    return None


def _ssh_connect_kwargs(host_ip: str) -> dict[str, object]:
    config = get_server_log_config(host_ip)
    if not config:
        raise LogAnalyzerError(f'Aucune source de logs web configurée pour {host_ip}.')

    username = config.get('ssh_user', '').strip()
    password = config.get('ssh_password', '')
    if not username:
        raise LogAnalyzerError(f'SSH user manquant pour {host_ip}.')

    kw: dict[str, object] = {
        'hostname': host_ip,
        'port': int(config.get('ssh_port', getattr(settings, 'LOG_HOST_SSH_PORT', 22))),
        'username': username,
        'timeout': int(getattr(settings, 'LOG_SSH_CONNECT_TIMEOUT_SEC', 15)),
        'allow_agent': False,
        'look_for_keys': False,
        'banner_timeout': int(getattr(settings, 'LOG_SSH_CONNECT_TIMEOUT_SEC', 15)),
    }
    if password != '':
        kw['password'] = password
    return kw


def get_resolved_log_path(host_ip: str) -> str:
    """Dernier fichier access.log effectivement lu pour ce serveur."""
    return _resolved_log_paths.get(host_ip, '')


def _log_line_limit() -> int:
    return int(getattr(settings, 'LOG_READ_LINE_LIMIT', 10000))


def _use_sudo() -> bool:
    return getattr(settings, 'LOG_SSH_USE_SUDO', True)


def _candidate_log_paths(host_ip: str, preferred: str | None = None) -> list[str]:
    config = get_server_log_config(host_ip) or {}
    extra = config.get('log_file_paths') or getattr(
        settings,
        'LOG_FILE_PATH_CANDIDATES',
        list(DEFAULT_LOG_CANDIDATES),
    )
    ordered: list[str] = []
    for path in [preferred, config.get('log_file_path'), *extra, *DEFAULT_LOG_CANDIDATES]:
        if path and path not in ordered:
            ordered.append(str(path))
    return ordered


def _content_has_access_lines(content: str) -> bool:
    if not content or not content.strip():
        return False
    for line in content.splitlines():
        if parse_combined_log_line(line):
            return True
    return False


def _latest_timestamp_in_content(content: str) -> datetime | None:
    """Dernière entrée parsée — sert à choisir le journal le plus à jour."""
    latest: datetime | None = None
    for line in content.splitlines():
        parsed = parse_combined_log_line(line)
        if parsed is None:
            continue
        dt = parsed.get('datetime')
        if isinstance(dt, datetime) and (latest is None or dt > latest):
            latest = dt
    return latest


def _log_content_score(content: str, mtime: float) -> tuple[float, float]:
    latest = _latest_timestamp_in_content(content)
    ts_score = latest.timestamp() if latest else 0.0
    return (ts_score, mtime)


def _local_file_mtime(path: str) -> float:
    try:
        return Path(path).stat().st_mtime
    except OSError:
        return 0.0


def _pick_freshest_candidate(
    candidates: list[tuple[str, str, tuple[float, float]]],
) -> tuple[str, str] | None:
    if not candidates:
        return None
    content, path, _ = max(candidates, key=lambda item: item[2])
    return content, path


def _tail_local_file(path: str, max_lines: int | None = None) -> str | None:
    limit = max_lines or _log_line_limit()
    log_path = Path(path)
    if not log_path.is_file():
        return None
    try:
        with log_path.open('r', encoding='utf-8', errors='replace') as handle:
            return ''.join(deque(handle, maxlen=limit))
    except OSError:
        return None


def _tail_local_with_sudo(path: str, password: str, max_lines: int | None = None) -> str | None:
    if not _use_sudo():
        return None
    limit = max_lines or _log_line_limit()
    attempts: list[list[str]] = [['sudo', '-n', 'tail', '-n', str(limit), path]]
    if password:
        attempts.append(['sudo', '-S', 'tail', '-n', str(limit), path])

    for cmd in attempts:
        try:
            proc = subprocess.run(
                cmd,
                input=f'{password}\n' if cmd[1] == '-S' and password else None,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout
    return None


def _read_local_log(host_ip: str, paths: list[str], password: str = '') -> tuple[str, str] | None:
    candidates: list[tuple[str, str, tuple[float, float]]] = []

    for path in paths:
        for content in (
            _tail_local_file(path),
            _tail_local_with_sudo(path, password) if password or _use_sudo() else None,
        ):
            if not content or not _content_has_access_lines(content):
                continue
            score = _log_content_score(content, _local_file_mtime(path))
            candidates.append((content, path, score))

    picked = _pick_freshest_candidate(candidates)
    return picked


def _ssh_exec(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    _, stdout, stderr = client.exec_command(command, timeout=30)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors='replace')
    err = stderr.read().decode(errors='replace').strip()
    return exit_code, out, err


def _remote_read_commands(path: str, password: str) -> list[str]:
    path_q = shlex.quote(path)
    limit = _log_line_limit()
    commands = [
        f'tail -n {limit} {path_q} 2>/dev/null',
        f'cat {path_q} 2>/dev/null',
        f'sudo -n tail -n {limit} {path_q} 2>/dev/null',
    ]
    if password:
        pwd_q = shlex.quote(password)
        commands.append(
            f'echo {pwd_q} | sudo -S tail -n {limit} {path_q} 2>/dev/null',
        )
    return commands


def _remote_file_mtime(client: paramiko.SSHClient, path: str) -> float:
    path_q = shlex.quote(path)
    exit_code, out, _ = _ssh_exec(client, f'stat -c %Y {path_q} 2>/dev/null')
    if exit_code != 0:
        return 0.0
    try:
        return float(out.strip())
    except ValueError:
        return 0.0


def _read_log_via_ssh(
    host_ip: str,
    paths: list[str],
    password: str,
) -> tuple[str, str]:
    kw = _ssh_connect_kwargs(host_ip)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    failures: list[str] = []
    candidates: list[tuple[str, str, tuple[float, float]]] = []

    try:
        client.connect(**kw)
        for path in paths:
            mtime = _remote_file_mtime(client, path)
            for command in _remote_read_commands(path, password):
                exit_code, out, err = _ssh_exec(client, command)
                if exit_code == 0 and _content_has_access_lines(out):
                    score = _log_content_score(out, mtime)
                    candidates.append((out, path, score))
                    break
                if err and 'Permission denied' not in err:
                    failures.append(f'{path}: {err}')
    except LogAnalyzerError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LogAnalyzerError(
            f'Connexion SSH vers {host_ip} impossible : {exc}',
        ) from exc
    finally:
        client.close()

    picked = _pick_freshest_candidate(candidates)
    if picked:
        return picked

    detail = failures[0] if failures else 'fichier introuvable ou permissions insuffisantes'
    tried = ', '.join(paths)
    raise LogAnalyzerError(
        f'Impossible de lire access.log sur {host_ip} ({tried}). {detail} '
        'Vérifiez Apache/Nginx, le chemin du log et les droits SSH (utilisateur adm ou sudo).',
    )


def fetch_remote_log_content(host_ip: str, log_path: str | None = None) -> str:
    """Récupère access.log en local (même VM) puis via SSH si nécessaire."""
    config = get_server_log_config(host_ip)
    if not config:
        raise LogAnalyzerError(f'Aucune source de logs web configurée pour {host_ip}.')

    password = str(config.get('ssh_password', ''))
    paths = _candidate_log_paths(host_ip, log_path)

    local_result = _read_local_log(host_ip, paths, password)
    if local_result:
        content, resolved = local_result
        _resolved_log_paths[host_ip] = resolved
        return content

    content, resolved = _read_log_via_ssh(host_ip, paths, password)
    _resolved_log_paths[host_ip] = resolved
    return content


def _parse_apache_timestamp(raw: str) -> datetime | None:
    for fmt in ('%d/%b/%Y:%H:%M:%S %z', '%d/%b/%Y:%H:%M:%S'):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def parse_combined_log_line(line: str) -> dict[str, object] | None:
    """Parse une ligne Combined Log Format ; retourne None si non reconnue."""
    line = line.strip()
    if not line:
        return None
    match = COMBINED_LOG_RE.match(line)
    if not match:
        return None

    data = match.groupdict()
    dt = _parse_apache_timestamp(data['timestamp'])
    data['datetime'] = dt
    data['date_display'] = dt.strftime('%d/%m/%Y') if dt else '—'
    data['time_display'] = dt.strftime('%H:%M:%S') if dt else '—'
    return data


def parse_access_log_entries(
    content: str,
    host_ip: str,
    host_name: str,
) -> list[dict[str, object]]:
    """Transforme le contenu brut en entrées structurées."""
    entries: list[dict[str, object]] = []
    for line in content.splitlines():
        parsed = parse_combined_log_line(line)
        if parsed is None:
            continue
        entries.append({
            'host_ip': host_ip,
            'host_name': host_name,
            'date': parsed['date_display'],
            'time': parsed['time_display'],
            'datetime': parsed['datetime'],
            'url': str(parsed['url']),
            'status': str(parsed['status']),
            'ip': str(parsed['ip']),
            'method': str(parsed['method']),
        })
    return entries


def _parse_filter_date(value: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        return None


def _matches_type_log(status: str, type_log: str) -> bool:
    if not type_log:
        return True
    if status == '-':
        return type_log == 'erreur'
    code = int(status)
    if type_log == 'erreur':
        return code >= 400
    if type_log == 'normal':
        return code < 400
    return True


def filter_access_entries(
    entries: list[dict[str, object]],
    *,
    date_debut: str = '',
    date_fin: str = '',
    keyword: str = '',
    type_log: str = '',
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    """Filtre les entrées access.log ; retourne (aperçu, top pages, total)."""
    start = _parse_filter_date(date_debut)
    end = _parse_filter_date(date_fin)
    terms = [t.strip().lower() for t in keyword.split() if t.strip()]
    filtered: list[dict[str, object]] = []

    for entry in entries:
        dt = entry.get('datetime')
        if start and isinstance(dt, datetime) and dt.date() < start:
            continue
        if end and isinstance(dt, datetime) and dt.date() > end:
            continue
        if not _matches_type_log(str(entry['status']), type_log):
            continue
        if terms:
            url_lower = str(entry['url']).lower()
            if not all(term in url_lower for term in terms):
                continue
        filtered.append(entry)

    filtered.sort(
        key=lambda item: item['datetime'].timestamp() if isinstance(item.get('datetime'), datetime) else 0,
        reverse=True,
    )

    page_hits = Counter(str(entry['url']) for entry in filtered)
    top_pages = [
        {'url': url, 'hits': hits}
        for url, hits in page_hits.most_common(TOP_LIMIT)
    ]
    total = len(filtered)

    display = filtered[:FILTER_LIMIT]
    for entry in display:
        entry.pop('datetime', None)
    return display, top_pages, total


def fetch_filtered_access_logs(
    hosts: list[tuple[str, str]],
    *,
    date_debut: str = '',
    date_fin: str = '',
    keyword: str = '',
    type_log: str = '',
    content_cache: dict[str, str] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int, str | None]:
    """
    Lit les access.log distants et applique les filtres.
    Retourne (entrées affichées, top pages, total filtré, erreur).
    """
    cache = content_cache if content_cache is not None else {}
    all_entries: list[dict[str, object]] = []
    errors: list[str] = []

    for host_ip, host_name in hosts:
        if not get_server_log_config(host_ip):
            continue
        try:
            if host_ip not in cache:
                cache[host_ip] = fetch_remote_log_content(host_ip)
            all_entries.extend(
                parse_access_log_entries(cache[host_ip], host_ip, host_name),
            )
        except LogAnalyzerError as exc:
            errors.append(f'{host_name} ({host_ip}) : {exc}')

    display, top_pages, total = filter_access_entries(
        all_entries,
        date_debut=date_debut,
        date_fin=date_fin,
        keyword=keyword,
        type_log=type_log,
    )
    error_msg = None
    if errors and not display:
        configured = [h for h in hosts if get_server_log_config(h[0])]
        if len(errors) >= len(configured):
            error_msg = errors[0]
    elif not display and not all_entries:
        error_msg = 'Journal vide ou format de log non reconnu sur le serveur.'
    elif errors and display:
        pass
    elif errors:
        error_msg = errors[0]
    return display, top_pages, total, error_msg


def analyze_access_log(content: str) -> dict[str, object]:
    """Agrège les statistiques à partir du contenu brut du access.log."""
    page_hits: Counter[str] = Counter()
    errors_404: Counter[str] = Counter()
    status_codes: Counter[str] = Counter()
    ip_hits: Counter[str] = Counter()
    traffic_by_day: Counter[str] = Counter()
    traffic_by_hour: Counter[str] = Counter()
    recent_visits: list[dict[str, object]] = []
    lines_parsed = 0
    lines_skipped = 0
    total_404 = 0

    for line in content.splitlines():
        parsed = parse_combined_log_line(line)
        if parsed is None:
            lines_skipped += 1
            continue

        lines_parsed += 1
        url = str(parsed['url'])
        status = str(parsed['status'])
        ip = str(parsed['ip'])
        dt = parsed.get('datetime')

        page_hits[url] += 1
        status_codes[status] += 1
        ip_hits[ip] += 1
        if status == '404':
            errors_404[url] += 1
            total_404 += 1
        if isinstance(dt, datetime):
            traffic_by_day[dt.strftime('%d/%m/%Y')] += 1
            traffic_by_hour[dt.strftime('%H:00')] += 1

        recent_visits.append({
            'date': parsed['date_display'],
            'time': parsed['time_display'],
            'url': url,
            'ip': ip,
            'status': status,
            'method': parsed['method'],
            'datetime': dt,
        })

    recent_visits.sort(
        key=lambda item: item['datetime'].timestamp() if item.get('datetime') else 0,
        reverse=True,
    )
    for visit in recent_visits:
        visit.pop('datetime', None)

    total_requests = lines_parsed
    incidence_404_pct = round((total_404 / total_requests) * 100, 1) if total_requests else 0.0

    top_pages = [{'url': url, 'hits': hits} for url, hits in page_hits.most_common(TOP_LIMIT)]
    top_404 = [{'url': url, 'count': count} for url, count in errors_404.most_common(TOP_LIMIT)]
    top_ips = [{'ip': ip, 'hits': hits} for ip, hits in ip_hits.most_common(TOP_LIMIT)]
    visits_by_day = [
        {'day': day, 'hits': hits}
        for day, hits in sorted(
            traffic_by_day.items(),
            key=lambda item: datetime.strptime(item[0], '%d/%m/%Y'),
            reverse=True,
        )[:TOP_LIMIT]
    ]
    visits_by_hour = [
        {'hour': hour, 'hits': hits}
        for hour, hits in sorted(traffic_by_hour.items())
    ]

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
        'total_404': total_404,
        'incidence_404_pct': incidence_404_pct,
        'unique_pages': len(page_hits),
        'top_pages': top_pages,
        'errors_404': top_404,
        'status_codes': status_breakdown,
        'top_ips': top_ips,
        'recent_visits': recent_visits[:RECENT_LIMIT],
        'visits_by_day': visits_by_day,
        'visits_by_hour': visits_by_hour,
        'lines_parsed': lines_parsed,
        'lines_skipped': lines_skipped,
    }


def get_log_statistics_for_host(host_ip: str) -> dict[str, object]:
    """Point d'entrée : SSH + analyse du access.log pour un serveur donné."""
    config = get_server_log_config(host_ip)
    if not config:
        raise LogAnalyzerError(f'Aucune source de logs web configurée pour {host_ip}.')

    content = fetch_remote_log_content(host_ip)
    stats = analyze_access_log(content)
    stats['log_file'] = get_resolved_log_path(host_ip) or config.get('log_file_path', '')
    stats['host'] = host_ip
    return stats


def aggregate_access_log_metrics(host_ips: list[str]) -> dict[str, object]:
    """Agrège les métriques des serveurs UP disposant d'une config log."""
    total_requests = 0
    total_404 = 0

    for ip in host_ips:
        if not get_server_log_config(ip):
            continue
        try:
            stats = get_log_statistics_for_host(ip)
        except LogAnalyzerError:
            continue
        total_requests += int(stats['total_requests'])
        total_404 += int(stats['total_404'])

    incidence_404_pct = round((total_404 / total_requests) * 100, 1) if total_requests else 0.0
    return {
        'total_requests': total_requests,
        'total_404': total_404,
        'incidence_404_pct': incidence_404_pct,
    }


def get_log_statistics(log_path: str | None = None) -> dict[str, object]:
    """Compatibilité : analyse le serveur LOG_HOST_IP par défaut."""
    host = getattr(settings, 'LOG_HOST_IP', '192.168.1.11').strip()
    if log_path:
        content = fetch_remote_log_content(host, log_path)
        stats = analyze_access_log(content)
        stats['log_file'] = log_path
        stats['host'] = host
        return stats
    return get_log_statistics_for_host(host)
