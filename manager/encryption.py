"""Symmetric encryption for secrets stored at rest.

Secrets (Apple account password, device private keys) are stored encrypted
using AES via ``cryptography``'s Fernet construction. The key is derived
from Django's ``SECRET_KEY`` so nothing extra needs to be persisted.
"""

import base64
import hashlib

from django.conf import settings

from cryptography.fernet import Fernet

_PREFIX = "crypt:"


def _fernet():
    key = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_text(value):
    """Encrypt ``value`` for storage. Empty/None values stay empty."""
    if not value:
        return ""
    token = _fernet().encrypt(str(value).encode("utf-8")).decode("ascii")
    return _PREFIX + token


def decrypt_text(value):
    """Decrypt a value previously stored with :func:`encrypt_text`."""
    if not value:
        return ""
    if not value.startswith(_PREFIX):
        # Written before encryption was introduced (or left in plaintext).
        return value
    return _fernet().decrypt(value[len(_PREFIX):].encode("ascii")).decode("utf-8")