from django import template

from logs.network_probe import resolve_server_name

register = template.Library()


@register.filter
def niveau_badge(niveau):
    n = (niveau or '').upper()
    if 'CRIT' in n or 'ERROR' in n or 'ERR' in n:
        return 'error'
    if 'WARN' in n or 'ATT' in n:
        return 'warn'
    if 'INFO' in n:
        return 'info'
    return 'ok'


@register.filter
def severite_badge(severite):
    s = (severite or '').upper()
    if 'CRIT' in s or 'MAJEUR' in s:
        return 'majeur'
    if 'MINEUR' in s or 'WARN' in s:
        return 'mineur'
    return 'nouveau'


@register.filter
def server_display_name(serveur):
    if serveur is None:
        return ''
    return resolve_server_name(serveur.adresse_ip, serveur.nom_serveur)


@register.filter
def server_dot(index):
    dots = ['gray', 'blue', 'orange']
    return dots[index % len(dots)]


@register.filter
def initials(name):
    parts = (name or '').split()
    if len(parts) >= 2:
        return (parts[0][0] + parts[-1][0]).upper()
    return (name[:2] if name else '?').upper()
