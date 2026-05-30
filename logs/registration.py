"""Inscription publique pour le modèle Utilisateur."""

from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone

from logs.models import Utilisateur
from logs.password_reset import validate_new_password

DEFAULT_REGISTRATION_ROLE = 'analyste'


def validate_registration(nom, prenom, email, password, password_confirm):
    """Retourne une liste de messages d'erreur (vide si tout est valide)."""
    errors = []
    nom = (nom or '').strip()
    prenom = (prenom or '').strip()
    email = (email or '').strip()

    if not nom:
        errors.append('Le nom est obligatoire.')
    elif len(nom) > 100:
        errors.append('Le nom ne peut pas dépasser 100 caractères.')

    if not prenom:
        errors.append('Le prénom est obligatoire.')
    elif len(prenom) > 100:
        errors.append('Le prénom ne peut pas dépasser 100 caractères.')

    if not email:
        errors.append("L'adresse e-mail est obligatoire.")
    else:
        try:
            validate_email(email)
        except ValidationError:
            errors.append("L'adresse e-mail n'est pas valide.")
        else:
            if Utilisateur.objects.filter(email__iexact=email).exists():
                errors.append('Un compte existe déjà avec cette adresse e-mail.')

    errors.extend(validate_new_password(password, password_confirm))
    return errors


def register_user(nom, prenom, email, password, password_confirm, role=DEFAULT_REGISTRATION_ROLE):
    """
    Crée un utilisateur après validation.
    Retourne (utilisateur, errors).
    """
    errors = validate_registration(nom, prenom, email, password, password_confirm)
    if errors:
        return None, errors

    utilisateur = Utilisateur(
        nom=nom.strip(),
        prenom=prenom.strip(),
        email=email.strip().lower(),
        mot_de_passe='',
        role=role,
        date_creation=timezone.now(),
    )
    utilisateur.set_password(password)
    utilisateur.save()
    return utilisateur, []
