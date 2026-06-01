"""Tests unitaires — analyse des access.log (Combined Log Format)."""
from django.test import SimpleTestCase

from logs.services.log_analyzer import (
    analyze_access_log,
    filter_access_entries,
    parse_access_log_entries,
    parse_combined_log_line,
    resolve_visitor_ip,
)

SAMPLE_LOG = """\
192.168.1.5 - - [31/May/2026:10:00:01 +0000] "GET /index HTTP/1.1" 200 1234
192.168.1.5 - - [31/May/2026:10:00:02 +0000] "GET /about HTTP/1.1" 200 800
192.168.1.5 - - [31/May/2026:10:00:03 +0000] "GET /missing HTTP/1.1" 404 512
192.168.1.6 - - [31/May/2026:10:00:04 +0000] "GET /error HTTP/1.1" 500 0
192.168.1.6 - - [31/May/2026:10:00:05 +0000] "GET /index HTTP/1.1" 200 1234
invalid line should be skipped
"""


class LogAnalyzerParseTest(SimpleTestCase):
    def test_parse_combined_log_line_valid(self):
        line = (
            '192.168.1.5 - - [31/May/2026:10:00:01 +0000] '
            '"GET /index HTTP/1.1" 200 1234'
        )
        parsed = parse_combined_log_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['ip'], '192.168.1.5')
        self.assertEqual(parsed['method'], 'GET')
        self.assertEqual(parsed['url'], '/index')
        self.assertEqual(parsed['status'], '200')

    def test_parse_combined_log_line_invalid(self):
        self.assertIsNone(parse_combined_log_line(''))
        self.assertIsNone(parse_combined_log_line('not a log line'))

    def test_parse_ngrok_external_visitor_ip(self):
        line = (
            '86.241.32.15 192.168.1.11 - - [01/Jun/2026:10:23:45 +0000] '
            '"GET / HTTP/1.1" 200 1234'
        )
        parsed = parse_combined_log_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['ip'], '86.241.32.15')
        self.assertNotEqual(parsed['ip'], '192.168.1.11')

    def test_parse_ngrok_local_visitor_ip(self):
        line = (
            '- 192.168.1.50 - - [01/Jun/2026:10:23:45 +0000] '
            '"GET / HTTP/1.1" 200 1234'
        )
        parsed = parse_combined_log_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['ip'], '192.168.1.50')

    def test_resolve_visitor_ip_helper(self):
        self.assertEqual(resolve_visitor_ip('86.241.32.15', '192.168.1.11'), '86.241.32.15')
        self.assertEqual(resolve_visitor_ip('-', '192.168.1.50'), '192.168.1.50')
        self.assertEqual(resolve_visitor_ip('192.168.1.5'), '192.168.1.5')

    def test_analyze_access_log_ignores_vm_ip_with_ngrok(self):
        ngrok_log = (
            '86.241.32.15 192.168.1.11 - - [01/Jun/2026:10:00:01 +0000] '
            '"GET / HTTP/1.1" 200 100\n'
            '- 192.168.1.50 - - [01/Jun/2026:10:00:02 +0000] '
            '"GET /about HTTP/1.1" 200 200\n'
        )
        stats = analyze_access_log(ngrok_log)
        top_ips = {row['ip'] for row in stats['top_ips']}

        self.assertIn('86.241.32.15', top_ips)
        self.assertIn('192.168.1.50', top_ips)
        self.assertNotIn('192.168.1.11', top_ips)

    def test_parse_access_log_entries(self):
        entries = parse_access_log_entries(SAMPLE_LOG, '192.168.1.11', 'Site témoin')
        self.assertEqual(len(entries), 5)
        self.assertEqual(entries[0]['url'], '/index')
        self.assertEqual(entries[0]['host_ip'], '192.168.1.11')


class LogAnalyzerAnalyzeTest(SimpleTestCase):
    def test_analyze_access_log_stats(self):
        stats = analyze_access_log(SAMPLE_LOG)

        self.assertEqual(stats['total_requests'], 5)
        self.assertEqual(stats['total_404'], 1)
        self.assertEqual(stats['unique_pages'], 4)
        self.assertEqual(stats['top_pages'][0]['url'], '/index')
        self.assertEqual(stats['top_pages'][0]['hits'], 2)

    def test_filter_access_entries_by_type_erreur(self):
        entries = parse_access_log_entries(SAMPLE_LOG, '192.168.1.11', 'Site témoin')
        display, top_pages, total = filter_access_entries(
            entries,
            type_log='erreur',
        )

        self.assertEqual(total, 2)
        statuses = {str(row['status']) for row in display}
        self.assertIn('404', statuses)
        self.assertIn('500', statuses)

    def test_filter_access_entries_by_keyword(self):
        entries = parse_access_log_entries(SAMPLE_LOG, '192.168.1.11', 'Site témoin')
        display, _, total = filter_access_entries(entries, keyword='index')

        self.assertEqual(total, 2)
        self.assertTrue(all('index' in str(row['url']).lower() for row in display))


class LogAnalyzerFreshnessTest(SimpleTestCase):
    def test_pick_freshest_log_by_timestamp(self):
        from logs.services.log_analyzer import _pick_freshest_candidate, _log_content_score

        old_log = (
            '192.168.1.1 - - [01/May/2026:08:00:00 +0000] "GET /old HTTP/1.1" 200 100\n'
        )
        new_log = (
            '192.168.1.1 - - [31/May/2026:18:00:00 +0000] "GET /new HTTP/1.1" 200 100\n'
        )
        candidates = [
            (old_log, '/var/log/apache2/access.log', _log_content_score(old_log, 1000.0)),
            (new_log, '/var/log/nginx/access.log', _log_content_score(new_log, 500.0)),
        ]
        content, path = _pick_freshest_candidate(candidates)

        self.assertEqual(path, '/var/log/nginx/access.log')
        self.assertIn('/new', content)
