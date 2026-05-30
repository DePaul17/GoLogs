from django import template

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
def server_dot(index):
    dots = ['gray', 'blue', 'orange']
    return dots[index % len(dots)]


@register.filter
def initials(name):
    parts = (name or '').split()
    if len(parts) >= 2:
        return (parts[0][0] + parts[-1][0]).upper()
    return (name[:2] if name else '?').upper()
