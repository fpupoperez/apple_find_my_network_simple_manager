"""Synchronously fetch and store locations (cron / one-off runs)."""

from django.core.management.base import BaseCommand, CommandError

from manager import tasks
from manager.models import AppleAccount


class Command(BaseCommand):
    help = "Fetch location history from Apple and store it (runs synchronously)."

    def add_arguments(self, parser):
        parser.add_argument("--account", help="Only fetch for this account name/email.")
        parser.add_argument("--days", type=int, default=7, help="Report history window in days.")
        parser.add_argument("--all", action="store_true",
                            help="Fetch for every active account.")

    def handle(self, *args, **options):
        if options["account"] and options["all"]:
            raise CommandError("Use either --account or --all, not both.")
        if options["days"] < 1:
            raise CommandError("--days must be at least 1.")

        if options["all"]:
            results = tasks.fetch_all_locations(days=options["days"])
            for pk, result in results.items():
                self._report(pk, result)
            return

        if options["account"]:
            accounts = AppleAccount.objects.filter(name=options["account"])
            if not accounts:
                accounts = AppleAccount.objects.filter(email=options["account"])
            if accounts.count() != 1:
                raise CommandError("Could not find exactly one account for '%s'."
                                   % options["account"])
            pk = accounts.first().pk
        else:
            pk = AppleAccount.objects.filter(active=True).values_list("pk", flat=True).first()
            if pk is None:
                raise CommandError("No active accounts to fetch for.")
        self._report(pk, tasks.fetch_locations(pk, days=options["days"]))

    def _report(self, pk, result):
        if result.get("status") == "ok":
            self.stdout.write(self.style.SUCCESS(
                "account %s: %s" % (pk, result.get("message", "ok"))))
        else:
            self.stdout.write(self.style.ERROR(
                "account %s: %s" % (pk, result.get("message") or result.get("status"))))