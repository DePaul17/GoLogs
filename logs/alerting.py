"""Module de génération et de mise à jour des alertes automatiques."""

from django.utils import timezone
from logs.models import Anomalie, Alerte


def compute_severity(anomalie):
    if anomalie.score is not None:
        score = float(anomalie.score)
        if score >= 80:
            return 'CRITIQUE'
        if score >= 50:
            return 'MAJEUR'
        return 'MINEURE'

    text = anomalie.type_anomalie.lower()
    if 'crit' in text or 'erreur' in text or 'fatal' in text:
        return 'CRITIQUE'
    if 'warn' in text or 'alerte' in text:
        return 'MAJEUR'
    return 'MINEURE'


def compute_channel(anomalie):
    if 'security' in anomalie.type_anomalie.lower() or 'auth' in anomalie.type_anomalie.lower():
        return 'SECURITE'
    return 'TABLEAU_DE_BORD'


def already_has_alert(anomalie):
    return Alerte.objects.filter(anomalie=anomalie).exists()


def create_alert(anomalie):
    if already_has_alert(anomalie):
        return None

    alert = Alerte.objects.create(
        anomalie=anomalie,
        severite=compute_severity(anomalie),
        canal=compute_channel(anomalie),
        statut='NOUVEAU',
        date_alerte=timezone.now(),
    )
    return alert


def generate_alerts_for_undetected_anomalies():
    created = []
    for anomalie in Anomalie.objects.all():
        if not already_has_alert(anomalie):
            alert = create_alert(anomalie)
            if alert:
                created.append(alert)
    return created


def update_alert_status(id_alerte, statut):
    alert = Alerte.objects.filter(id_alerte=id_alerte).first()
    if not alert:
        raise ValueError(f"Alerte introuvable : {id_alerte}")
    alert.statut = statut
    alert.save()
    return alert
