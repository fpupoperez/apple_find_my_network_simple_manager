"""Create (or update) the periodic django-q2 schedule that fetches locations.

Example:  python manage.py schedule_fetch --every 15 --minutes
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import now

from django_q.models import Schedule


class Command(BaseCommand):
    help = "Schedule periodic background location fetches via django-q2."

    def add_arguments(self, parser):
        parser.add_argument("--every", type=int, default=15,
                            help="Every N minutes/hours (see --unit).")
        parser.add_argument("--unit", choices=["minutes", "hours"],
                            default="minutes", help="Unit for --every.")
        parser.add_argument("--days", type=int, default=7,
                            help="History window fetched on each run.")
        parser.add_argument("--name", default="fetch-locations",
                            help="Schedule row name (upserts by this name).")

    def handle(self, *args, **options):
        if options["every"] < 1:
            raise CommandError("--every must be at least 1.")
        if options["days"] < 1:
            raise CommandError("--days must be at least 1.")

        kwargs = {
            "name": options["name"],
            "func": "manager.tasks.fetch_all_locations",
            "args": "{}".format(options["days"]),
            "schedule_type": (Schedule.MINUTES if options["unit"] == "minutes"
                              else Schedule.HOURLY),
            "repeats": -1,
        }
        if options["unit"] == "minutes":
            if options["every"] > 59:
                raise CommandError("--every must be 1-59 for --unit minutes.")
            kwargs["minutes"] = options["every"]
        else:
            kwargs["cron"] = "0 */{} * * *".format(options["every"])

        schedule, created = Schedule.objects.update_or_create(
            name=options["name"], defaults=kwargs)
        self.stdout.write(self.style.SUCCESS(
            "%s schedule '%s' (next run at %s)." % (
                "Created" if created else "Updated",
                schedule, schedule.next_run or now())))