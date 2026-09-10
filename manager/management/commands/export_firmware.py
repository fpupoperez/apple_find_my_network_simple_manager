"""Export the native ESP-IDF ``main.c`` firmware for a device from the CLI."""

import sys
from uuid import UUID

from django.core.management.base import BaseCommand, CommandError

from manager import esp_idf
from manager.models import Device


class Command(BaseCommand):
    help = "Print (or save) the ESP-IDF main.c firmware for a device."

    def add_arguments(self, parser):
        parser.add_argument("device", help="Device id or name.")
        parser.add_argument("--out", "-o", help="Write to this file instead of stdout.")
        parser.add_argument("--broadcast", type=int, help="Override beacon window (seconds).")
        parser.add_argument("--sleep", type=int, help="Override delay between beacons (minutes).")

    def handle(self, *args, **options):
        arg = options["device"]
        try:
            devices = Device.objects.filter(pk=UUID(arg))
        except (ValueError, TypeError, AttributeError):
            devices = Device.objects.none()
        if not devices:
            devices = Device.objects.filter(name=arg)
        if devices.count() != 1:
            raise CommandError(
                "Could not find exactly one device for '%s' (found %d)."
                % (options["device"], devices.count()))
        device = devices.first()
        if not device.advertisement_key_hex:
            raise CommandError("Device '%s' has no advertisement key yet." % device)
        source = esp_idf.generate_firmware_c(
            device,
            broadcast_duration_sec=options.get("broadcast"),
            sleep_duration_min=options.get("sleep"),
        )
        if options["out"]:
            with open(options["out"], "w", encoding="utf-8") as fh:
                fh.write(source)
            self.stdout.write(self.style.SUCCESS("Wrote %s" % options["out"]))
        else:
            sys.stdout.write(source)
            if not source.endswith("\n"):
                sys.stdout.write("\n")