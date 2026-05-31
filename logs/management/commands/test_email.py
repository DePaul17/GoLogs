from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Envoie un e-mail de test pour vérifier la configuration SMTP (.env)"

    def add_arguments(self, parser):
        parser.add_argument(
            'destinataire',
            type=str,
            help='Adresse e-mail qui doit recevoir le message de test',
        )

    def handle(self, *args, **options):
        if not settings.EMAIL_HOST:
            raise CommandError(
                'EMAIL_HOST n\'est pas configuré. Copiez .env.example vers .env '
                'et renseignez les paramètres SMTP (Gmail, etc.).'
            )

        destinataire = options['destinataire']
        send_mail(
            subject='GoLogs — Test SMTP',
            message=(
                'Si vous lisez ce message, l\'envoi d\'e-mails GoLogs fonctionne.\n'
                f'Serveur SMTP : {settings.EMAIL_HOST}\n'
                f'Expéditeur : {settings.DEFAULT_FROM_EMAIL}'
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[destinataire],
            fail_silently=False,
        )
        self.stdout.write(
            self.style.SUCCESS(
                f'E-mail de test envoyé à {destinataire} via {settings.EMAIL_HOST}'
            )
        )
