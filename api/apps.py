"""AppConfig for the ``api`` app (REST endpoints under /api/v1/)."""

from django.apps import AppConfig
from django.contrib.auth.signals import user_logged_out


class ApiConfig(AppConfig):
    name = "api"
    verbose_name = "Find My manager API"

    def ready(self):
        from rest_framework.authtoken.models import Token

        def revoke_access_token(sender, request, user, **kwargs):
            if user and user.is_authenticated:
                Token.objects.filter(user=user).delete()

        user_logged_out.connect(revoke_access_token, dispatch_uid="api.revoke_access_token")