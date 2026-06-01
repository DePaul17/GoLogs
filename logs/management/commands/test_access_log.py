"""Diagnostic : lecture access.log (local puis SSH)."""
from django.conf import settings
from django.core.management.base import BaseCommand

from logs.services.log_analyzer import (
    LogAnalyzerError,
    analyze_access_log,
    fetch_remote_log_content,
    get_resolved_log_path,
    get_server_log_config,
)


class Command(BaseCommand):
    help = 'Teste la lecture du access.log pour un serveur monitoré.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--host',
            default=getattr(settings, 'LOG_HOST_IP', '192.168.1.11'),
            help='IP du serveur (défaut : LOG_HOST_IP)',
        )

    def handle(self, *args, **options):
        host = options['host'].strip()
        config = get_server_log_config(host)
        if not config:
            self.stderr.write(self.style.ERROR(f'Aucune config log pour {host}'))
            return

        self.stdout.write(f'Serveur : {host}')
        self.stdout.write(f'Utilisateur SSH : {config.get("ssh_user", "—")}')
        self.stdout.write(f'Chemins testés : {config.get("log_file_paths") or config.get("log_file_path")}')

        try:
            content = fetch_remote_log_content(host)
        except LogAnalyzerError as exc:
            self.stderr.write(self.style.ERROR(f'Échec : {exc}'))
            return

        resolved = get_resolved_log_path(host) or '(inconnu)'
        stats = analyze_access_log(content)
        self.stdout.write(self.style.SUCCESS(f'Fichier lu : {resolved}'))
        self.stdout.write(f'Lignes parsées : {stats["lines_parsed"]} (ignorées : {stats["lines_skipped"]})')
        self.stdout.write(f'Requêtes HTTP : {stats["total_requests"]}')
        self.stdout.write(f'Erreurs 404 : {stats["total_404"]}')
