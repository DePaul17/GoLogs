from django.contrib import admin
from .models import (
    Utilisateur,
    SourceLog,
    Serveur,
    LogEntree,
    Anomalie,
    Alerte,
    Rapport,
    Commentaire,
)


@admin.register(Utilisateur)
class UtilisateurAdmin(admin.ModelAdmin):
    list_display = ('id_utilisateur', 'nom', 'prenom', 'email', 'role', 'date_creation')
    search_fields = ('nom', 'prenom', 'email', 'role')


@admin.register(SourceLog)
class SourceLogAdmin(admin.ModelAdmin):
    list_display = ('id_source', 'nom_source', 'type_source', 'adresse_ip', 'statut', 'date_ajout')
    search_fields = ('nom_source', 'type_source', 'adresse_ip')


@admin.register(Serveur)
class ServeurAdmin(admin.ModelAdmin):
    list_display = ('id_serveur', 'nom_serveur', 'adresse_ip', 'systeme_exploitation', 'localisation', 'statut', 'date_ajout')
    search_fields = ('nom_serveur', 'adresse_ip', 'localisation')


@admin.register(LogEntree)
class LogEntreeAdmin(admin.ModelAdmin):
    list_display = ('id_log', 'source', 'serveur', 'horodatage', 'niveau', 'service', 'statut_traitement', 'date_insertion')
    list_filter = ('niveau', 'service', 'statut_traitement')
    search_fields = ('message',)


@admin.register(Anomalie)
class AnomalieAdmin(admin.ModelAdmin):
    list_display = ('id_anomalie', 'log', 'type_anomalie', 'score', 'date_detection')
    search_fields = ('type_anomalie', 'description')


@admin.register(Alerte)
class AlerteAdmin(admin.ModelAdmin):
    list_display = ('id_alerte', 'anomalie', 'severite', 'canal', 'statut', 'date_alerte')
    list_filter = ('severite', 'canal', 'statut')


@admin.register(Rapport)
class RapportAdmin(admin.ModelAdmin):
    list_display = ('id_rapport', 'utilisateur', 'type_rapport', 'date_debut', 'date_fin', 'date_generation')
    search_fields = ('type_rapport',)


@admin.register(Commentaire)
class CommentaireAdmin(admin.ModelAdmin):
    list_display = ('id_commentaire', 'log', 'utilisateur', 'date_commentaire')
    search_fields = ('contenu',)
