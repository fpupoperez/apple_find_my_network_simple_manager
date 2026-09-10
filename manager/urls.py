from django.contrib.auth import views as auth_views
from django.urls import path, re_path
from django.views.generic import RedirectView
from django.templatetags.static import static

from manager import views

app_name = "manager"

urlpatterns = [
    path("login/", views.ManagerLoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),

    path("", views.dashboard, name="dashboard"),
    path("profile/", views.profile, name="profile"),

    re_path(r"^favicon\.ico$", RedirectView.as_view(
        url=static("manager/img/favicon.ico"), permanent=True), name="favicon"),

    path("accounts/", views.account_list, name="account_list"),
    path("accounts/new/", views.account_create, name="account_create"),
    path("accounts/<uuid:pk>/", views.account_detail, name="account_detail"),
    path("accounts/<uuid:pk>/edit/", views.account_update, name="account_update"),
    path("accounts/<uuid:pk>/delete/", views.account_delete, name="account_delete"),
    path("accounts/<uuid:pk>/config.ini", views.config_ini_download, name="account_config_ini"),
    path("accounts/<uuid:pk>/login/", views.account_findmy_login, name="account_findmy_login"),

    path("devices/", views.device_list, name="device_list"),
    path("devices/new/", views.device_create, name="device_create"),
    path("devices/<uuid:pk>/", views.device_detail, name="device_detail"),
    path("devices/<uuid:pk>/history/", views.device_history, name="device_history"),
    path("devices/<uuid:pk>/history/data/", views.DeviceHistoryDatatable.as_view(),
         name="device_history_data"),
    path("devices/<uuid:pk>/edit/", views.device_update, name="device_update"),
    path("devices/<uuid:pk>/delete/", views.device_delete, name="device_delete"),
    path("devices/<uuid:pk>/export-micropython/", views.device_export_micropython, name="device_export_micropython"),
    path("devices/<uuid:pk>/export-firmware/", views.device_export_firmware, name="device_export_firmware"),
    path("devices/<uuid:pk>/export-arduino/", views.device_export_arduino, name="device_export_arduino"),

    path("export/keys/", views.macless_keyfile, name="macless_keyfile"),

    path("map/", views.map_view, name="map"),
    path("fetch/", views.fetch_all_locations, name="fetch_all_locations"),
    path("accounts/<uuid:pk>/fetch/", views.account_fetch_locations, name="account_fetch_locations"),
]