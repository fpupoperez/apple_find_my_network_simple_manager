from django.contrib.auth.middleware import LoginRequiredMiddleware

# Paths that must stay reachable without a session login. The headless allauth
# endpoints and the DRF API carry their own authentication (session via the
# web UI, Bearer tokens for apps), the admin has its own login flow, and
# static assets must load so the login page itself can render.
PUBLIC_PATHS = ("/favicon.ico",)
PUBLIC_PREFIXES = ("/api/", "/admin/", "/static/", "/account/")


class ManagerLoginRequiredMiddleware(LoginRequiredMiddleware):
    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.path_info in PUBLIC_PATHS or request.path_info.startswith(PUBLIC_PREFIXES):
            return None
        return super().process_view(request, view_func, view_args, view_kwargs)