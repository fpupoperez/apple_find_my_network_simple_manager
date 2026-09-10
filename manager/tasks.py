"""Background tasks (django-q2) that query Apple's Find My network.

Uses the `findmy` PyPI package (FindMy.py) to log in with the stored Apple ID,
fetch the decrypted location reports for the account's devices and persist
them as :class:`manager.models.DeviceLocation` rows so they can be shown on
the map.
"""

import logging

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


def _safe_close(fm):
    """Best-effort synchronous close for FindMy.py's sync AppleAccount.

    ``close()`` is a coroutine that must be awaited on the same event loop
    the sync account used, otherwise Python warns "coroutine was never
    awaited" and, on failure, leaks nothing we care about.
    """
    import asyncio

    coro = fm.close()
    try:
        loop = getattr(fm, "_evt_loop", None)
        if loop is None:
            asyncio.run(coro)
        else:
            loop.run_until_complete(coro)
    except Exception:
        # Loop closed / thread mismatch: cleanup is best-effort. Discard the
        # coroutine so Python doesn't complain about it never being awaited.
        try:
            coro.close()
        except Exception:
            pass


def _state_dir():
    path = settings.FINDMY_STATE_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def _state_paths(account_pk):
    """Returns (account_session_path, anisette_libs_path)."""
    base = _state_dir()
    return base / "account_{}.json".format(account_pk), str(base / "ani_libs.bin")


def _anisette_provider():
    from findmy import LocalAnisetteProvider, RemoteAnisetteProvider

    url = getattr(settings, "FINDMY_ANISETTE_URL", "") or None
    if url:
        return RemoteAnisetteProvider(url)
    libs = str(_state_dir() / "ani_libs.bin")
    return LocalAnisetteProvider(libs_path=libs)


def _build_accessories(devices):
    """Map a FindMy.py accessory object onto its Django Device."""
    from findmy import FixedRollingKeyPairAccessory

    accessories = {}
    for device in devices:
        if not device.private_key_hex or not device.advertisement_key_hex:
            logger.warning("Device %s has no keys, skipping.", device)
            continue
        accessory = FixedRollingKeyPairAccessory(
            private_keys=[device.private_key],
            name=device.name,
            identifier=str(device.pk),
        )
        accessories[accessory] = device
    return accessories


def fetch_locations(account_pk, days=7):
    """Fetch up to ``days`` days of location history for one account's devices.

    Decrypted reports are stored in the database. Apple's login session is
    cached on disk between runs so 2FA is only needed once.
    """
    from findmy import AppleAccount as FindMyAccount
    from findmy import LoginState, UnauthorizedError
    from manager.models import AppleAccount, DeviceLocation

    try:
        account = AppleAccount.objects.get(pk=account_pk)
    except AppleAccount.DoesNotExist:
        return {"status": "error", "message": "account no longer exists"}

    def record(status, message):
        account.last_fetch_at = timezone.now()
        account.last_fetch_status = status
        account.last_fetch_message = message
        account.save(update_fields=["last_fetch_at", "last_fetch_status", "last_fetch_message"])

    password = account.get_password()
    if not password:
        record("error", "No Apple ID password stored for this account.")
        return {"status": "error", "message": "no password stored"}

    devices = list(account.devices.filter(active=True))
    accessories = _build_accessories(devices)
    if not accessories:
        record("error", "No active devices with a keypair.")
        return {"status": "error", "message": "no devices with keys"}

    state_path, libs_path = _state_paths(account.pk)

    # Restore a cached session, otherwise log in with the stored credentials.
    restored = False
    try:
        fm = FindMyAccount.from_json(state_path, anisette_libs_path=libs_path)
        restored = True
    except (FileNotFoundError, ValueError, KeyError):
        fm = FindMyAccount(_anisette_provider())

    try:
        if not restored or fm.login_state != LoginState.LOGGED_IN:
            state = fm.login(account.email, password)
            if state == LoginState.REQUIRE_2FA:
                record("needs_2fa", "Two-factor authentication is required. Open the "
                       "Apple account page and use Sign in to Apple once to complete login.")
                return {"status": "needs_2fa"}

        try:
            reports_map = fm.fetch_location_history(list(accessories))
        except UnauthorizedError:
            # Session expired: re-authenticate once and retry.
            state = fm.login(account.email, password)
            if state == LoginState.REQUIRE_2FA:
                record("needs_2fa", "Two-factor authentication is required again. "
                       "Open the Apple account page and use Sign in to Apple.")
                return {"status": "needs_2fa"}
            reports_map = fm.fetch_location_history(list(accessories))

        stored = created = 0
        for accessory, reports in reports_map.items():
            device = accessories[accessory]
            for report in reports:
                _, was_created = DeviceLocation.objects.get_or_create(
                    device=device,
                    timestamp=report.timestamp,
                    defaults={
                        "latitude": report.latitude,
                        "longitude": report.longitude,
                        "horizontal_accuracy": report.horizontal_accuracy,
                        "status": report.status,
                        "confidence": report.confidence,
                    },
                )
                stored += 1
                created += int(was_created)

        if not restored:
            fm.to_json(state_path)  # cache the session for background reuse

        record("ok", "Stored {} location report(s) ({} new).".format(stored, created))
        return {"status": "ok", "stored": stored, "created": created}
    except Exception as exc:  # keep a record of any Apple-side failure
        logger.exception("FindMy fetch failed for account %s", account.name)
        message = "{}: {}".format(type(exc).__name__, exc)
        status = "error"
        if "503" in str(exc):
            status = "throttled"
            message += (" — Apple's login endpoint is throttling this account/device. "
                        "Wait and retry; repeated attempts extend the block.")
        record(status, message)
        return {"status": status, "message": str(exc)}
    finally:
        _safe_close(fm)


def login_findmy(account_pk, retries=5):
    """Background Apple login — same work as ``manage.py login_findmy``.

    Caches the session file used by :func:`fetch_locations`. If Apple requires
    2FA, pending state is stored so the account page can finish verification.
    """
    from manager import findmy_auth
    from manager.models import AppleAccount

    try:
        account = AppleAccount.objects.get(pk=account_pk)
    except AppleAccount.DoesNotExist:
        return {"status": "error", "message": "account no longer exists"}

    def record(status, message):
        account.last_fetch_at = timezone.now()
        account.last_fetch_status = status
        account.last_fetch_message = message
        account.save(update_fields=["last_fetch_at", "last_fetch_status", "last_fetch_message"])

    result = findmy_auth.start_login(account, retries=retries)
    if result["status"] == "logged_in":
        record("ok", "Apple session cached. Location fetches can reuse it.")
    elif result["status"] == "needs_2fa":
        record("needs_2fa", "Two-factor authentication is required. Complete it on the "
               "Apple account page (Sign in to Apple).")
    else:
        message = result.get("message") or "Apple sign-in failed."
        status = "throttled" if "503" in message else "error"
        record(status, message)
    return result


def fetch_all_locations(days=7):
    """Fetch locations for every active account (used by scheduled tasks)."""
    from manager.models import AppleAccount

    results = {}
    for account in AppleAccount.objects.filter(active=True, password_encrypted__gt=""):
        results[account.pk] = fetch_locations(account.pk, days=days)
    return results