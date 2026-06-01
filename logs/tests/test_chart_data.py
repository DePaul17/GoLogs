"""Tests unitaires — préparation des graphiques serveur."""
from django.test import SimpleTestCase

from logs.services.chart_data import (
    aggregate_status_donut,
    build_chart_payload,
    build_top_pages_bar,
)


class ChartDataTest(SimpleTestCase):
    def test_aggregate_status_donut_groups_codes(self):
        status_codes = [
            {'code': '200', 'count': 120, 'percent': 80.0},
            {'code': '404', 'count': 20, 'percent': 13.3},
            {'code': '500', 'count': 5, 'percent': 3.3},
            {'code': '502', 'count': 5, 'percent': 3.3},
            {'code': '301', 'count': 10, 'percent': 6.7},
        ]
        result = aggregate_status_donut(status_codes)

        self.assertEqual(result['labels'], [
            '200 OK',
            '404 Not Found',
            'Erreurs serveur (5xx)',
        ])
        self.assertEqual(result['data'], [120, 20, 10])
        self.assertEqual(result['colors'], ['#66bb6a', '#ffc107', '#c62828'])
        self.assertEqual(result['total'], 150)

    def test_aggregate_status_donut_omits_empty_slices(self):
        result = aggregate_status_donut([{'code': '200', 'count': 5, 'percent': 100.0}])
        self.assertEqual(result['labels'], ['200 OK'])
        self.assertEqual(result['data'], [5])

    def test_build_top_pages_bar_truncates_long_urls(self):
        top_pages = [
            {'url': '/index', 'hits': 10},
            {'url': '/very/long/path/that/should/be/truncated/for/chart', 'hits': 3},
        ]
        result = build_top_pages_bar(top_pages)

        self.assertEqual(len(result['labels']), 2)
        self.assertTrue(result['labels'][1].endswith('…'))
        self.assertEqual(result['full_labels'][1], top_pages[1]['url'])
        self.assertEqual(result['data'], [10, 3])

    def test_build_chart_payload_structure(self):
        stats = {
            'top_pages': [{'url': '/home', 'hits': 42}],
            'status_codes': [
                {'code': '200', 'count': 40, 'percent': 95.0},
                {'code': '404', 'count': 2, 'percent': 5.0},
            ],
        }
        payload = build_chart_payload(stats)

        self.assertIn('top_pages', payload)
        self.assertIn('status_donut', payload)
        self.assertEqual(payload['top_pages']['data'], [42])
        self.assertEqual(payload['status_donut']['data'], [40, 2])
