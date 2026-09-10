"""Apple ID login shared by ``login_findmy`` and the account-page task.

Caches the Find My session on disk so background fetches can reuse it.
When Apple asks for 2FA, in-progress state is written to a pending file
so the browser can finish verification the same way the management
command does interactively.
"""

import json
import re
import time

from manager import tasks

LOGIN_RETRIES = 5
LOGIN_RETRY_WAIT_SEC = 15


def session_path(account):
    return tasks._state_paths(account.pk)[0]


def pending_path(account):
    return tasks._state_dir() / "account_{}.pending.json".format(account.pk)


def pending_meta_path(account):
    return tasks._state_dir() / "account_{}.pending.meta.json".format(account.pk)


def session_cached(account):
    return session_path(account).is_file()


def login_in_progress(account):
    return pending_path(account).is_file()


def clear_pending(account):
    pending_path(account).unlink(missing_ok=True)
    pending_meta_path(account).unlink(missing_ok=True)


def save_pending_meta(account, data):
    path = pending_meta_path(account)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def load_pending_meta(account):
    path = pending_meta_path(account)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def describe_method(index, method):
    phone = getattr(method, "phone_number", None)
    if phone:
        return {"index": index, "kind": "sms", "label": "SMS (%s)" % phone}
    return {"index": index, "kind": "trusted_device", "label": "Trusted device"}


def describe_methods(fm):
    return [describe_method(index, method) for index, method in enumerate(fm.get_2fa_methods())]


def login_with_retries(fm, email, password, retries=LOGIN_RETRIES, on_retry=None):
    """Same retry loop as ``manage.py login_findmy`` for transient Apple 5xx errors."""
    from findmy import UnhandledProtocolError

    attempts = max(1, int(retries))
    for attempt in range(1, attempts + 1):
        try:
            return fm.login(email, password)
        except UnhandledProtocolError as exc:
            transient = re.search(r"\b5\d\d\b", str(exc))
            if not transient or attempt == attempts:
                raise
            if on_retry:
                on_retry(exc, attempt, attempts)
            time.sleep(LOGIN_RETRY_WAIT_SEC)
    raise RuntimeError("Aborting after %d attempt(s)." % attempts)


def cache_session(fm, account):
    """Write the official session file used later by location fetches."""
    fm.to_json(session_path(account))
    clear_pending(account)


def start_login(account, retries=LOGIN_RETRIES, on_retry=None):
    """Log in with the stored Apple ID password. May return ``needs_2fa``.

    This is the non-interactive half of ``login_findmy``: authenticate,
    retry transient Apple errors, and either cache the session or park
    2FA state for the UI (or the command) to finish.
    """
    from findmy import AppleAccount as FindMyAccount, LoginState

    password = account.get_password()
    if not password:
        return {"status": "error", "message": "Store the Apple ID password first."}

    fm = FindMyAccount(tasks._anisette_provider())
    try:
        state = login_with_retries(
            fm, account.email, password, retries=retries, on_retry=on_retry)
        if state == LoginState.LOGGED_IN:
            cache_session(fm, account)
            return {"status": "logged_in"}
        if state == LoginState.REQUIRE_2FA:
            methods = describe_methods(fm)
            fm.to_json(pending_path(account))
            save_pending_meta(account, {"methods": methods, "requested": None})
            return {"status": "needs_2fa", "methods": methods}
        return {"status": "error", "message": "Login did not complete (state=%s)." % state}
    except Exception as exc:
        return {"status": "error", "message": friendly_login_error(exc)}
    finally:
        tasks._safe_close(fm)


def _restore_pending(account):
    from findmy import AppleAccount as FindMyAccount

    path = pending_path(account)
    if not path.is_file():
        return None
    return FindMyAccount.from_json(path, anisette_libs_path=tasks._state_paths(account.pk)[1])


def _get_method(fm, method_index):
    methods = list(fm.get_2fa_methods())
    try:
        return methods[int(method_index)]
    except (TypeError, ValueError, IndexError):
        return None


def request_2fa(account, method_index):
    """Ask Apple to send/display a 2FA challenge for the chosen method."""
    fm = None
    try:
        fm = _restore_pending(account)
        if fm is None:
            return {"status": "error", "message": "No login in progress. Sign in to Apple again."}
        method = _get_method(fm, method_index)
        if method is None:
            return {"status": "error", "message": "Choose a valid verification method."}
        method.request()
        info = describe_method(int(method_index), method)
        fm.to_json(pending_path(account))
        meta = load_pending_meta(account)
        meta["requested"] = info
        save_pending_meta(account, meta)
        return {"status": "code_sent", "method": info}
    except Exception as exc:
        return {"status": "error", "message": friendly_login_error(exc)}
    finally:
        if fm is not None:
            tasks._safe_close(fm)


def submit_2fa(account, method_index, code):
    """Complete 2FA and cache the session when Apple accepts the code."""
    from findmy import LoginState

    fm = None
    try:
        fm = _restore_pending(account)
        if fm is None:
            return {"status": "error", "message": "No login in progress. Sign in to Apple again."}
        method = _get_method(fm, method_index)
        if method is None:
            return {"status": "error", "message": "Choose a valid verification method."}
        state = method.submit((code or "").strip())
        if state == LoginState.LOGGED_IN:
            cache_session(fm, account)
            return {"status": "logged_in"}
        return {"status": "error", "message": "The verification code was not accepted."}
    except Exception as exc:
        return {"status": "error", "message": friendly_login_error(exc)}
    finally:
        if fm is not None:
            tasks._safe_close(fm)


def friendly_login_error(exc):
    name = type(exc).__name__
    msg = str(exc)
    if name == "UnhandledProtocolError" and "503" in msg:
        return (
            "Apple's authentication server rejected the request with HTTP 503 "
            "(Service Temporarily Unavailable). This is Apple-side throttling/blocking "
            "of the login endpoint, not a credentials problem. Wait and retry; "
            "repeated attempts extend the block."
        )
    if name == "InvalidCredentialsError":
        return "Apple rejected the stored Apple ID email/password: %s" % msg
    return "%s: %s" % (name, msg)
