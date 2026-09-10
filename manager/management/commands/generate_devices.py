"""Generate one or more devices with fresh P-224 keypairs."""

from django.core.management.base import BaseCommand, CommandError

from manager import keygen
from manager.models import AppleAccount, Device


class Command(BaseCommand):
    help = "Create N devices, each with a freshly generated P-224 keypair."

    def add_arguments(self, parser):
        parser.add_argument("count", nargs="?", type=int, default=1)
        parser.add_argument("--account", required=True,
                            help="Apple account name or email to attach the devices to.")
        parser.add_argument("--prefix", default="tag", help="Name prefix (default: 'tag').")

    def handle(self, *args, **options):
        if options["count"] < 1 or options["count"] > 100:
            raise CommandError("count must be between 1 and 100")
        accounts = AppleAccount.objects.filter(name=options["account"])
        if not accounts:
            accounts = AppleAccount.objects.filter(email=options["account"])
        if accounts.count() != 1:
            raise CommandError("Could not find exactly one account for '%s'." % options["account"])
        account = accounts.first()

        for index in range(options["count"]):
            private_bytes, advertisement_bytes = keygen.generate_keypair()
            device = Device.objects.create(
                account=account,
                name="%s-%02d" % (options["prefix"], index + 1),
                private_key_hex=private_bytes.hex(),
                advertisement_key_hex=advertisement_bytes.hex(),
            )
            self.stdout.write(
                "%s\t%24s\t%s device=%d"
                % (device.name, advertisement_bytes.hex(), private_bytes.hex(), device.pk))
        self.stdout.write(self.style.SUCCESS("Created %d device(s)." % options["count"]))