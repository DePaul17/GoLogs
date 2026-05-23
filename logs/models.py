from django.contrib.auth.hashers import check_password, make_password
from django.db import models


class Utilisateur(models.Model):
    id_utilisateur = models.AutoField(primary_key=True)
    nom = models.CharField(max_length=100)
    prenom = models.CharField(max_length=100)
    email = models.EmailField(max_length=150, unique=True)
    mot_de_passe = models.CharField(max_length=255)
    role = models.CharField(max_length=20)
    date_creation = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'UTILISATEUR'
        verbose_name = 'Utilisateur'
        verbose_name_plural = 'Utilisateurs'

    def set_password(self, raw_password):
        self.mot_de_passe = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.mot_de_passe)

    def __str__(self):
        return f"{self.prenom} {self.nom}"


class SourceLog(models.Model):
    id_source = models.AutoField(primary_key=True)
    nom_source = models.CharField(max_length=100)
    type_source = models.CharField(max_length=30)
    adresse_ip = models.CharField(max_length=45, null=True, blank=True)
    description = models.CharField(max_length=255, null=True, blank=True)
    statut = models.CharField(max_length=20, null=True, blank=True)
    date_ajout = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'SOURCE_LOG'
        verbose_name = 'Source de log'
        verbose_name_plural = 'Sources de logs'

    def __str__(self):
        return self.nom_source


class Serveur(models.Model):
    id_serveur = models.AutoField(primary_key=True)
    nom_serveur = models.CharField(max_length=100)
    adresse_ip = models.CharField(max_length=45)
    systeme_exploitation = models.CharField(max_length=100, null=True, blank=True)
    localisation = models.CharField(max_length=100, null=True, blank=True)
    statut = models.CharField(max_length=20, null=True, blank=True)
    date_ajout = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'SERVEUR'
        verbose_name = 'Serveur'
        verbose_name_plural = 'Serveurs'

    def __str__(self):
        return self.nom_serveur


class LogEntree(models.Model):
    id_log = models.AutoField(primary_key=True)
    source = models.ForeignKey(SourceLog, on_delete=models.CASCADE, db_column='ID_SOURCE')
    serveur = models.ForeignKey(Serveur, on_delete=models.CASCADE, db_column='ID_SERVEUR')
    horodatage = models.DateTimeField()
    niveau = models.CharField(max_length=20)
    service = models.CharField(max_length=100, null=True, blank=True)
    message = models.CharField(max_length=255)
    statut_traitement = models.CharField(max_length=20, null=True, blank=True)
    date_insertion = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'LOG_ENTREE'
        verbose_name = 'Entrée de log'
        verbose_name_plural = 'Entrées de logs'

    def __str__(self):
        return f"[{self.niveau}] {self.service or 'service inconnu'} - {self.message[:50]}"


class Anomalie(models.Model):
    id_anomalie = models.AutoField(primary_key=True)
    log = models.ForeignKey(LogEntree, on_delete=models.CASCADE, db_column='ID_LOG')
    type_anomalie = models.CharField(max_length=100)
    score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    description = models.CharField(max_length=255, null=True, blank=True)
    date_detection = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'ANOMALIE'
        verbose_name = 'Anomalie'
        verbose_name_plural = 'Anomalies'

    def __str__(self):
        return f"{self.type_anomalie} ({self.score or 'N/A'})"


class Alerte(models.Model):
    id_alerte = models.AutoField(primary_key=True)
    anomalie = models.ForeignKey(Anomalie, on_delete=models.CASCADE, db_column='ID_ANOMALIE')
    severite = models.CharField(max_length=20)
    canal = models.CharField(max_length=20)
    statut = models.CharField(max_length=20, null=True, blank=True)
    date_alerte = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'ALERTE'
        verbose_name = 'Alerte'
        verbose_name_plural = 'Alertes'

    def __str__(self):
        return f"{self.severite} - {self.canal}"


class Rapport(models.Model):
    id_rapport = models.AutoField(primary_key=True)
    utilisateur = models.ForeignKey(Utilisateur, on_delete=models.CASCADE, db_column='ID_UTILISATEUR')
    type_rapport = models.CharField(max_length=100)
    date_debut = models.DateField()
    date_fin = models.DateField()
    chemin_fichier = models.CharField(max_length=255, null=True, blank=True)
    date_generation = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'RAPPORT'
        verbose_name = 'Rapport'
        verbose_name_plural = 'Rapports'

    def __str__(self):
        return f"{self.type_rapport} ({self.date_debut} → {self.date_fin})"


class Commentaire(models.Model):
    id_commentaire = models.AutoField(primary_key=True)
    log = models.ForeignKey(LogEntree, on_delete=models.CASCADE, db_column='ID_LOG')
    utilisateur = models.ForeignKey(Utilisateur, on_delete=models.CASCADE, db_column='ID_UTILISATEUR')
    contenu = models.CharField(max_length=255)
    date_commentaire = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'COMMENTAIRE'
        verbose_name = 'Commentaire'
        verbose_name_plural = 'Commentaires'

    def __str__(self):
        return f"Commentaire de {self.utilisateur} sur log #{self.log.id_log}"
