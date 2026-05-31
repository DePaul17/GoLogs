"""Réinitialisation de mot de passe pour le modèle Utilisateur."""

from django.conf import settings
from django.core import signing
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.urls import reverse

from logs.models import Utilisateur

TOKEN_SALT = 'gologs-password-reset'
MIN_PASSWORD_LENGTH = 8


def make_reset_token(user_id):
    return signing.dumps({'uid': user_id}, salt=TOKEN_SALT)


def parse_reset_token(token):
    """Retourne l'id utilisateur si le jeton est valide, sinon None."""
    max_age = getattr(settings, 'PASSWORD_RESET_TIMEOUT', 86400)
    try:
        data = signing.loads(token, salt=TOKEN_SALT, max_age=max_age)
        return data['uid']
    except (signing.BadSignature, signing.SignatureExpired):
        return None


def validate_new_password(password, password_confirm):
    errors = []
    if password != password_confirm:
        errors.append('Les mots de passe ne correspondent pas.')
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(
            f'Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères.'
        )
    return errors


def build_reset_url(request, path):
    site_url = getattr(settings, 'SITE_URL', '').rstrip('/')
    if site_url:
        return f'{site_url}{path}'
    return request.build_absolute_uri(path)


def send_password_reset_email(request, utilisateur):
    token = make_reset_token(utilisateur.id_utilisateur)
    path = reverse(
        'password_reset_confirm',
        kwargs={'user_id': utilisateur.id_utilisateur, 'token': token},
    )
    reset_url = build_reset_url(request, path)
    subject = 'GoLogs — Réinitialisation de votre mot de passe'
    context = {
        'utilisateur': utilisateur,
        'reset_url': reset_url,
        'timeout_hours': getattr(settings, 'PASSWORD_RESET_TIMEOUT', 86400) // 3600,
    }
    text_body = render_to_string('logs/emails/password_reset.txt', context)
    html_body = render_to_string('logs/emails/password_reset.html', context)

    email = EmailMultiAlternatives(
        subject,
        text_body,
        settings.DEFAULT_FROM_EMAIL,
        [utilisateur.email],
    )
    email.attach_alternative(html_body, 'text/html')
    email.send(fail_silently=False)


def request_password_reset(request, email):
    """Envoie l'e-mail de réinitialisation si l'utilisateur existe."""
    utilisateur = Utilisateur.objects.filter(email__iexact=email.strip()).first()
    if utilisateur:
        send_password_reset_email(request, utilisateur)
        return True
    return False


def reset_password(user_id, token, new_password):
    """Met à jour le mot de passe si le jeton est valide. Retourne (ok, message_erreur)."""
    uid = parse_reset_token(token)
    if uid is None or uid != user_id:
        return False, 'Ce lien de réinitialisation est invalide ou a expiré.'

    utilisateur = Utilisateur.objects.filter(id_utilisateur=user_id).first()
    if not utilisateur:
        return False, 'Utilisateur introuvable.'

    utilisateur.set_password(new_password)
    utilisateur.save(update_fields=['mot_de_passe'])
    return True, None
