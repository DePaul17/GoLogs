"""
URL configuration for gologs project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.views.generic import RedirectView

from logs import views

urlpatterns = [
    path('', RedirectView.as_view(pattern_name='login', permanent=False), name='root'),
    path('admin/', admin.site.urls),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('servers/', views.servers_view, name='servers'),
    path('log-stats/', views.log_stats, name='log_stats'),
    path('export/server-logs/', views.export_server_logs_csv, name='export_server_logs'),
    path('import/logs/', views.import_logs_csv, name='import_logs_csv'),
    path('password-reset/', views.password_reset_request_view, name='password_reset'),
    path('password-reset/done/', views.password_reset_done_view, name='password_reset_done'),
    path(
        'password-reset/confirm/<int:user_id>/<str:token>/',
        views.password_reset_confirm_view,
        name='password_reset_confirm',
    ),
    path(
        'password-reset/complete/',
        views.password_reset_complete_view,
        name='password_reset_complete',
    ),
]
