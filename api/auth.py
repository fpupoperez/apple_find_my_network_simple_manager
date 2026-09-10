"""allauth headless token strategy and DRF authentication integration.

django-allauth's headless "app" client runs the whole auth flow (login,
signup, MFA, password reset...) using a per-client *session token*. Once a
user is authenticated, allauth calls :meth:`create_access_token` to hand back
a token the client can use against the rest of the API.

This module:

* :class:`DrfTokenStrategy` returns a
  :class:`rest_framework.authtoken.models.Token` as the headless access token,
  so a mobile client can authenticate against the DRF resource endpoints;
* :class:`DrfBearerTokenAuthentication` lets DRF accept that token when sent
  as ``Authorization: Bearer <token>`` (matching allauth's ``token_type``).

The session token used during the allauth flows themselves is the regular
Django session key (the default allauth strategy).
"""

from allauth.core.internal.httpkit import authenticated_user
from allauth.headless.tokens.strategies.sessions import SessionTokenStrategy
from rest_framework.authentication import TokenAuthentication, get_authorization_header
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed


class DrfTokenStrategy(SessionTokenStrategy):
    """Issue a DRF auth token as the post-auth access token."""

    def create_access_token(self, request):
        user = authenticated_user(request)
        if user is None:
            return None
        token, _ = Token.objects.get_or_create(user=user)
        return token.key

    def create_access_token_payload(self, request):
        access_token = self.create_access_token(request)
        if not access_token:
            return None
        return {"access_token": access_token, "token_type": "Bearer"}


class DrfBearerTokenAuthentication(TokenAuthentication):
    """DRF token auth tolerant of both the ``Token`` and ``Bearer`` schemes."""

    keyword = "Bearer"

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth:
            return None
        scheme = auth[0].lower().decode()
        if scheme not in ("bearer", "token"):
            return None
        if len(auth) < 2:
            raise AuthenticationFailed("Invalid token header. No credentials provided.")
        return self.authenticate_credentials(auth[1].decode())