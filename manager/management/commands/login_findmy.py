"""Interactive Apple login for an account, completing 2FA when required.

Run this once per Apple account so background django-q2 tasks can reuse the
cached session instead of prompting for a verification code. The account-page
button queues :func:`manager.tasks.login_findmy`, which uses the same login
and session-cache path.
"""

import sys

from django.core.management.base import BaseCommand, CommandError

from manager import findmy_auth, tasks
from manager.models import AppleAccount


class Command(BaseCommand):
    help = "Perform the interactive Find My login (incl. 2FA) for an Apple account."

    def add_arguments(self, parser):
        parser.add_argument("account", help="Apple account name or email.")
        parser.add_argument("--retries", type=int, default=findmy_auth.LOGIN_RETRIES,
                            help="Retries on transient Apple errors (HTTP 5xx).")

    def handle(self, *args, **options):
        from findmy import AppleAccount as FindMyAccount, LoginState

        accounts = AppleAccount.objects.filter(name=options["account"])
        if not accounts:
            accounts = AppleAccount.objects.filter(email=options["account"])
        if accounts.count() != 1:
            raise CommandError("Could not find exactly one account for '%s'." % options["account"])
        account = accounts.first()

        password = account.get_password()
        if not password:
            raise CommandError("No Apple ID password stored for '%s'." % account.name)

        state_path = findmy_auth.session_path(account)
        fm = FindMyAccount(tasks._anisette_provider())
        try:
            def on_retry(exc, attempt, attempts):
                self.stdout.write(self.style.WARNING(
                    "Apple returned a transient '%s' (attempt %d/%d); "
                    "waiting %ds and retrying..." % (
                        exc, attempt, attempts, findmy_auth.LOGIN_RETRY_WAIT_SEC)))

            state = findmy_auth.login_with_retries(
                fm, account.email, password, retries=options["retries"], on_retry=on_retry)
            if state == LoginState.REQUIRE_2FA:
                try:
                    state = self._complete_2fa(fm)
                except (KeyboardInterrupt, EOFError):
                    self.stdout.write(self.style.WARNING(
                        "\nLogin cancelled. No session file was written."))
                    sys.exit(1)

            if state == LoginState.LOGGED_IN:
                self.stdout.write(self.style.SUCCESS("Login successful; caching session."))
                findmy_auth.cache_session(fm, account)
            else:
                raise CommandError("Login did not complete (state=%s)." % state)
        except (CommandError,):
            raise
        except Exception as exc:
            raise CommandError(findmy_auth.friendly_login_error(exc)) from exc
        finally:
            tasks._safe_close(fm)

        self.stdout.write(self.style.SUCCESS(
            "Session cached. Background fetches will reuse it "
            "(path: %s)." % state_path))

    def _complete_2fa(self, fm):
        from findmy import SmsSecondFactorMethod, TrustedDeviceSecondFactorMethod

        self.stdout.write("This account requires two-factor authentication.")
        methods = fm.get_2fa_methods()
        for index, method in enumerate(methods):
            if isinstance(method, TrustedDeviceSecondFactorMethod):
                self.stdout.write("  %d - Trusted device" % index)
            elif isinstance(method, SmsSecondFactorMethod):
                self.stdout.write("  %d - SMS (%s)" % (index, method.phone_number))
        choice = input("Select a verification method: ")
        method = methods[int(choice)]
        method.request()
        code = input("Enter the verification code: ").strip()
        return method.submit(code)
