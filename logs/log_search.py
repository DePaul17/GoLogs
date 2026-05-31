"""Recherche textuelle sur les entrées de logs."""

from django.db.models import Q


def parse_search_terms(search_query):
    """Découpe la saisie en mots-clés (espaces, virgules)."""
    if not search_query:
        return []
    normalized = search_query.replace(',', ' ')
    return [term for term in normalized.split() if term]


def apply_log_search(queryset, search_query):
    """
    Filtre le queryset : chaque mot-clé doit apparaître dans au moins un champ du log.
    Permet de retrouver une ou plusieurs lignes correspondantes.
    """
    terms = parse_search_terms(search_query.strip())
    if not terms:
        return queryset

    for term in terms:
        queryset = queryset.filter(
            Q(message__icontains=term)
            | Q(service__icontains=term)
            | Q(niveau__icontains=term)
            | Q(statut_traitement__icontains=term)
            | Q(source__nom_source__icontains=term)
            | Q(serveur__nom_serveur__icontains=term)
        )
    return queryset
