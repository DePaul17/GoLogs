from logs.models import Utilisateur


def authenticate_user(email, raw_password):
    """Retourne l'utilisateur si les identifiants sont corrects, sinon None.

    Le mot de passe est vérifié avec le hachage stocké en base.
    """
    utilisateur = Utilisateur.objects.filter(email__iexact=email).first()
    if utilisateur and utilisateur.check_password(raw_password):
        return utilisateur
    return None
