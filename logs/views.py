from django.contrib import messages
from django.db.models import Q
from django.shortcuts import redirect, render

from logs.auth import authenticate_user
from logs.registration import register_user
from logs.log_search import apply_log_search, parse_search_terms
from logs.network_probe import (
    list_all_monitored_servers,
    resolve_server_name,
)
from logs.services.log_analyzer import (
    LogAnalyzerError,
    analyze_access_log,
    fetch_filtered_access_logs,
    fetch_remote_log_content,
    get_server_log_config,
)
from logs.models import Alerte, Anomalie, LogEntree, Rapport, SourceLog, Serveur, Utilisateur
from logs.password_reset import (
    parse_reset_token,
    request_password_reset,
    reset_password,
    validate_new_password,
)

SESSION_USER_ID = 'utilisateur_id'
SESSION_USER_NAME = 'utilisateur_nom'
SESSION_USER_ROLE = 'utilisateur_role'


def _is_authenticated(request):
    return SESSION_USER_ID in request.session


def login_view(request):
    if _is_authenticated(request):
        return redirect('dashboard')

    error = None
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        mot_de_passe = request.POST.get('mot_de_passe', '')
        utilisateur = authenticate_user(email, mot_de_passe)
        if utilisateur:
            request.session[SESSION_USER_ID] = utilisateur.id_utilisateur
            request.session[SESSION_USER_NAME] = f'{utilisateur.prenom} {utilisateur.nom}'
            request.session[SESSION_USER_ROLE] = utilisateur.role
            return redirect('dashboard')
        error = 'Email ou mot de passe incorrect.'

    return render(request, 'logs/login.html', {'error': error})


def register_view(request):
    if _is_authenticated(request):
        return redirect('dashboard')

    errors = []
    form_data = {}

    if request.method == 'POST':
        form_data = {
            'nom': request.POST.get('nom', '').strip(),
            'prenom': request.POST.get('prenom', '').strip(),
            'email': request.POST.get('email', '').strip(),
        }
        mot_de_passe = request.POST.get('mot_de_passe', '')
        mot_de_passe_confirm = request.POST.get('mot_de_passe_confirm', '')

        utilisateur, errors = register_user(
            form_data['nom'],
            form_data['prenom'],
            form_data['email'],
            mot_de_passe,
            mot_de_passe_confirm,
        )
        if utilisateur:
            messages.success(
                request,
                'Votre compte a été créé. Vous pouvez vous connecter.',
            )
            return redirect('login')

    return render(
        request,
        'logs/register.html',
        {'errors': errors, 'form': form_data},
    )


def logout_view(request):
    request.session.flush()
    return redirect('login')


def dashboard(request):
    if not _is_authenticated(request):
        return redirect('login')

    utilisateur = Utilisateur.objects.filter(
        id_utilisateur=request.session.get(SESSION_USER_ID)
    ).first()
    if not utilisateur:
        request.session.flush()
        return redirect('login')

    utilisateur_nom = f'{utilisateur.prenom} {utilisateur.nom}'
    request.session[SESSION_USER_NAME] = utilisateur_nom
    request.session[SESSION_USER_ROLE] = utilisateur.role

    is_admin = utilisateur.role.strip().lower() == 'admin'
    context = {
        'utilisateur_nom': utilisateur_nom,
        'utilisateur_prenom': utilisateur.prenom,
        'role': utilisateur.role,
        'is_admin': is_admin,
    }

    if is_admin:
        alert_search_query = request.GET.get('alert_q', '').strip()
        alert_severite_filter = request.GET.get('alert_severite', '').strip()
        alert_canal_filter = request.GET.get('alert_canal', '').strip()
        alert_statut_filter = request.GET.get('alert_statut', '').strip()
        alert_type_filter = request.GET.get('alert_type', '').strip()
        alert_date_debut = request.GET.get('alert_date_debut', '').strip()
        alert_date_fin = request.GET.get('alert_date_fin', '').strip()

        alertes_queryset = Alerte.objects.select_related(
            'anomalie',
            'anomalie__log',
            'anomalie__log__source',
            'anomalie__log__serveur',
        )
        alert_search_terms = parse_search_terms(alert_search_query)
        for term in alert_search_terms:
            alertes_queryset = alertes_queryset.filter(
                Q(severite__icontains=term)
                | Q(canal__icontains=term)
                | Q(statut__icontains=term)
                | Q(anomalie__type_anomalie__icontains=term)
                | Q(anomalie__description__icontains=term)
                | Q(anomalie__log__message__icontains=term)
                | Q(anomalie__log__service__icontains=term)
                | Q(anomalie__log__source__nom_source__icontains=term)
                | Q(anomalie__log__serveur__nom_serveur__icontains=term)
            )
        if alert_severite_filter:
            alertes_queryset = alertes_queryset.filter(
                severite__iexact=alert_severite_filter
            )
        if alert_canal_filter:
            alertes_queryset = alertes_queryset.filter(canal__iexact=alert_canal_filter)
        if alert_statut_filter:
            alertes_queryset = alertes_queryset.filter(statut__iexact=alert_statut_filter)
        if alert_type_filter:
            alertes_queryset = alertes_queryset.filter(
                anomalie__type_anomalie__iexact=alert_type_filter
            )
        if alert_date_debut:
            alertes_queryset = alertes_queryset.filter(
                date_alerte__date__gte=alert_date_debut
            )
        if alert_date_fin:
            alertes_queryset = alertes_queryset.filter(
                date_alerte__date__lte=alert_date_fin
            )

        filtered_alertes = alertes_queryset.order_by('-date_alerte')[:100]

        search_query = request.GET.get('q', '').strip()
        type_log = request.GET.get('type_log', '').strip()
        filtre_serveur = request.GET.get('filtre_serveur', '').strip()
        service_filter = request.GET.get('service', '').strip()
        source_filter = request.GET.get('source', '').strip()
        serveur_filter = request.GET.get('serveur', '').strip()
        date_debut = request.GET.get('date_debut', '').strip()
        date_fin = request.GET.get('date_fin', '').strip()

        logs_queryset = LogEntree.objects.select_related('source', 'serveur').all()
        search_terms = parse_search_terms(search_query)
        if search_terms:
            logs_queryset = apply_log_search(logs_queryset, search_query)
        if service_filter:
            logs_queryset = logs_queryset.filter(service__iexact=service_filter)
        if source_filter:
            logs_queryset = logs_queryset.filter(source_id=source_filter)
        if serveur_filter:
            logs_queryset = logs_queryset.filter(serveur_id=serveur_filter)
        if date_debut:
            logs_queryset = logs_queryset.filter(horodatage__date__gte=date_debut)
        if date_fin:
            logs_queryset = logs_queryset.filter(horodatage__date__lte=date_fin)

        filtered_logs = logs_queryset.order_by('-horodatage')[:100]

        tous_les_serveurs = list_all_monitored_servers()
        serveurs_en_marche = [entry for entry in tous_les_serveurs if entry['up']]
        serveur_ip = request.GET.get('serveur_ip', '').strip()
        serveur_logs = None
        serveur_logs_error = None
        serveur_actif = None
        log_content_cache: dict[str, str] = {}
        log_stats_cache: dict[str, dict] = {}

        def _load_log_content(host: str) -> str:
            if host not in log_content_cache:
                log_content_cache[host] = fetch_remote_log_content(host)
            return log_content_cache[host]

        def _load_log_stats(host: str) -> dict:
            if host not in log_stats_cache:
                stats = analyze_access_log(_load_log_content(host))
                config = get_server_log_config(host)
                stats['log_file'] = (
                    config.get('log_file_path', '/var/log/apache2/access.log')
                    if config else ''
                )
                stats['host'] = host
                log_stats_cache[host] = stats
            return log_stats_cache[host]

        filtres_actifs = any([
            search_query,
            date_debut,
            date_fin,
            type_log,
            filtre_serveur,
        ])
        access_logs_filtres: list[dict] = []
        access_logs_error = None

        if filtres_actifs:
            if filtre_serveur:
                host_targets = [(filtre_serveur, resolve_server_name(filtre_serveur))]
            else:
                host_targets = [
                    (entry['ip'], entry['nom'])
                    for entry in serveurs_en_marche
                    if get_server_log_config(entry['ip'])
                ]
            if not host_targets:
                access_logs_error = (
                    'Aucun serveur UP avec journal web disponible pour le filtrage.'
                )
            else:
                access_logs_filtres, access_logs_error = fetch_filtered_access_logs(
                    host_targets,
                    date_debut=date_debut,
                    date_fin=date_fin,
                    keyword=search_query,
                    type_log=type_log,
                    content_cache=log_content_cache,
                )

        if serveur_ip:
            serveur_actif = {
                'ip': serveur_ip,
                'nom': resolve_server_name(serveur_ip),
            }
            for entry in tous_les_serveurs:
                if entry['ip'] == serveur_ip:
                    serveur_actif['nom'] = entry['nom']
                    serveur_actif['serveur'] = entry.get('serveur')
                    break

            if get_server_log_config(serveur_ip):
                try:
                    serveur_logs = _load_log_stats(serveur_ip)
                except LogAnalyzerError as exc:
                    serveur_logs_error = str(exc)
            else:
                serveur_logs_error = (
                    'Aucun journal web configuré pour ce serveur. '
                    'Seul le Site témoin (192.168.1.11) expose un access.log Apache.'
                )

        up_ips = [entry['ip'] for entry in serveurs_en_marche]
        total_requests = 0
        total_404 = 0
        for ip in up_ips:
            if not get_server_log_config(ip):
                continue
            try:
                stats_host = _load_log_stats(ip)
            except LogAnalyzerError:
                continue
            total_requests += int(stats_host['total_requests'])
            total_404 += int(stats_host['total_404'])

        incidence_404_pct = round((total_404 / total_requests) * 100, 1) if total_requests else 0.0
        access_metrics = {
            'total_requests': total_requests,
            'total_404': total_404,
            'incidence_404_pct': incidence_404_pct,
        }

        context['stats'] = {
            'sources': SourceLog.objects.count(),
            'serveurs': len(serveurs_en_marche),
            'logs': access_metrics['total_requests'],
            'total_404': access_metrics['total_404'],
            'incidence_404_pct': access_metrics['incidence_404_pct'],
            'anomalies': Anomalie.objects.count(),
            'alertes': Alerte.objects.filter(statut='NOUVEAU').count(),
            'rapports': Rapport.objects.count(),
        }
        context['dernieres_alertes'] = filtered_alertes
        context['derniers_logs'] = filtered_logs
        context['alert_severites_disponibles'] = (
            Alerte.objects.order_by().values_list('severite', flat=True).distinct()
        )
        context['alert_canaux_disponibles'] = (
            Alerte.objects.order_by().values_list('canal', flat=True).distinct()
        )
        context['alert_statuts_disponibles'] = (
            Alerte.objects.order_by().values_list('statut', flat=True).distinct()
        )
        context['alert_types_disponibles'] = (
            Anomalie.objects.order_by().values_list('type_anomalie', flat=True).distinct()
        )
        context['alert_search_terms'] = alert_search_terms
        context['alert_filters'] = {
            'q': alert_search_query,
            'severite': alert_severite_filter,
            'canal': alert_canal_filter,
            'statut': alert_statut_filter,
            'type': alert_type_filter,
            'date_debut': alert_date_debut,
            'date_fin': alert_date_fin,
        }
        context['alertes_filtrees_count'] = alertes_queryset.count()
        context['alert_filtres_actifs'] = any(
            [
                alert_search_query,
                alert_severite_filter,
                alert_canal_filter,
                alert_statut_filter,
                alert_type_filter,
                alert_date_debut,
                alert_date_fin,
            ]
        )
        context['niveaux_disponibles'] = (
            LogEntree.objects.order_by()
            .values_list('niveau', flat=True)
            .distinct()
        )
        context['services_disponibles'] = (
            LogEntree.objects.exclude(service__isnull=True)
            .exclude(service='')
            .order_by()
            .values_list('service', flat=True)
            .distinct()
        )
        context['sources_disponibles'] = SourceLog.objects.order_by('nom_source')
        context['serveurs_disponibles'] = Serveur.objects.order_by('nom_serveur')
        context['serveurs_en_marche'] = serveurs_en_marche
        context['serveurs_log_disponibles'] = [
            entry for entry in serveurs_en_marche
            if get_server_log_config(entry['ip'])
        ]
        context['tous_les_serveurs'] = tous_les_serveurs
        context['serveur_ip'] = serveur_ip
        context['serveur_actif'] = serveur_actif
        context['serveur_logs'] = serveur_logs
        context['serveur_logs_error'] = serveur_logs_error
        context['search_terms'] = search_terms
        context['access_logs_filtres'] = access_logs_filtres
        context['access_logs_error'] = access_logs_error
        context['log_filters'] = {
            'q': search_query,
            'type_log': type_log,
            'filtre_serveur': filtre_serveur,
            'service': service_filter,
            'source': source_filter,
            'serveur': serveur_filter,
            'date_debut': date_debut,
            'date_fin': date_fin,
        }
        context['logs_filtres_count'] = len(access_logs_filtres)
        context['filtres_actifs'] = filtres_actifs

    return render(request, 'logs/dashboard.html', context)


def servers_view(request):
    if not _is_authenticated(request):
        return redirect('login')
    return redirect('/dashboard/#serveurs')


def log_stats(request):
    if not _is_authenticated(request):
        return redirect('login')
    from django.conf import settings

    host = getattr(settings, 'LOG_HOST_IP', '192.168.1.11')
    return redirect(f'/dashboard/?serveur_ip={host}#logs-serveur')


def password_reset_request_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        request_password_reset(request, email)
        return redirect('password_reset_done')
    return render(request, 'logs/password_reset_request.html')


def password_reset_done_view(request):
    from django.conf import settings

    return render(
        request,
        'logs/password_reset_done.html',
        {'email_reel': getattr(settings, 'EMAIL_USE_REAL_SMTP', False)},
    )


def password_reset_confirm_view(request, user_id, token):
    uid = parse_reset_token(token)
    utilisateur_exists = Utilisateur.objects.filter(id_utilisateur=user_id).exists()
    validlink = uid is not None and uid == user_id and utilisateur_exists

    if not validlink:
        return render(
            request,
            'logs/password_reset_confirm.html',
            {'validlink': False, 'errors': [], 'user_id': user_id, 'token': token},
        )

    errors = []
    if request.method == 'POST':
        mot_de_passe = request.POST.get('mot_de_passe', '')
        mot_de_passe_confirm = request.POST.get('mot_de_passe_confirm', '')
        errors = validate_new_password(mot_de_passe, mot_de_passe_confirm)
        if not errors:
            ok, error = reset_password(user_id, token, mot_de_passe)
            if ok:
                return redirect('password_reset_complete')
            errors = [error]
            validlink = False

    return render(
        request,
        'logs/password_reset_confirm.html',
        {
            'validlink': validlink,
            'errors': errors,
            'user_id': user_id,
            'token': token,
        },
    )


def password_reset_complete_view(request):
    return render(request, 'logs/password_reset_complete.html')
