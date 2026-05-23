from logs.models import Utilisateur


def authenticate_user(email, raw_password):
    """Retourne l'utilisateur si les identifiants sont corrects, sinon None."""
    utilisateur = Utilisateur.objects.filter(email__iexact=email).first()
    if utilisateur and utilisateur.check_password(raw_password):
        return utilisateur
    return None
