"""Models for the Find My device manager.

An :class:`AppleAccount` represents the Apple ID used by the companion
macless-haystack container to pull location reports from Apple's servers.
A :class:`Device` is a physical ESP32 tag broadcasting one P-224 keypair:
the *advertisement key* goes into the flashed MicroPython code, the
*private key* lets macless-haystack decrypt the received location reports.
"""

import base64
import hashlib
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse

from manager import encryption, keygen

AdvertisementKeyLength = 28


class EncryptedCharField(models.CharField):
    """CharField that transparently encrypts its value at rest."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_length", 400)
        super().__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return None
        return encryption.decrypt_text(value)

    def to_python(self, value):
        return value

    def get_prep_value(self, value):
        if value is None:
            return None
        return encryption.encrypt_text(value)


class UUIDPrimaryKeyModel(models.Model):
    """Application rows use a UUID primary key instead of an auto-increment int."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class OwnedQuerySet(models.QuerySet):
    """QuerySet mixin that scopes rows to the owning Django user."""

    owner_field = None

    def for_user(self, user):
        if user is None or not getattr(user, "is_authenticated", False):
            return self.none()
        return self.filter(**{self.owner_field: user})


class AppleAccountQuerySet(OwnedQuerySet):
    owner_field = "user"


class DeviceQuerySet(OwnedQuerySet):
    owner_field = "account__user"


class DeviceLocationQuerySet(OwnedQuerySet):
    owner_field = "device__account__user"


class AppleAccount(UUIDPrimaryKeyModel):
    """The user's Apple account used by macless-haystack."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="apple_accounts",
        on_delete=models.CASCADE,
        help_text="Django user who owns this Apple account and its devices.",
    )
    name = models.CharField(max_length=100, help_text="A friendly label, e.g. 'Home'.")
    email = models.EmailField()
    password_encrypted = models.CharField("Password", max_length=512, blank=True)
    active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_fetch_at = models.DateTimeField(
        null=True, blank=True, help_text="When locations were last fetched for this account.")
    last_fetch_status = models.CharField(
        max_length=32, default="", blank=True,
        help_text="Status of the last fetch job, e.g. 'ok', 'needs_2fa', 'error'.")
    last_fetch_message = models.TextField(
        blank=True, help_text="Detail message from the last fetch job.")

    objects = AppleAccountQuerySet.as_manager()

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "email"], name="uniq_apple_account_email_per_user"),
        ]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("manager:account_detail", args=[self.pk])

    def set_password(self, password):
        self.password_encrypted = encryption.encrypt_text(password)

    def get_password(self):
        """Decrypted Apple ID password (keep out of logs/templates unless needed)."""
        return encryption.decrypt_text(self.password_encrypted)

    @property
    def password_is_set(self):
        return bool(self.get_password())

    @property
    def device_count(self):
        return self.devices.count()


class Device(UUIDPrimaryKeyModel):
    """A single ESP32 Find-My locator tag and its keypair."""

    account = models.ForeignKey(
        AppleAccount, related_name="devices", on_delete=models.PROTECT,
        help_text="Apple account whose macless-haystack container will decrypt this tag.",
    )
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    advertisement_key_hex = EncryptedCharField(
        blank=True, help_text="28-byte P-224 advertisement (public) key as hex, "
        "e.g. from macless-haystack generate_keys.py.")

    private_key_hex = EncryptedCharField(
        blank=True, help_text="28-byte P-224 private key as hex. Never expose this "
        "to the device itself; only the macless-haystack container needs it.")

    active = models.BooleanField(default=True)
    broadcast_duration_sec = models.PositiveSmallIntegerField(
        default=10, help_text="Seconds the ESP32 stays awake beaconing after each wake-up.")
    sleep_duration_min = models.PositiveSmallIntegerField(
        default=5, help_text="Minutes the ESP32 spends in deep sleep between beacons.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = DeviceQuerySet.as_manager()

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(fields=["account", "name"], name="uniq_device_per_account"),
        ]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("manager:device_detail", args=[self.pk])

    def clean(self):
        super().clean()
        if self.advertisement_key_hex:
            self.advertisement_key_hex = self.advertisement_key_hex.strip().lower()
            if len(bytes.fromhex(self.advertisement_key_hex)) != AdvertisementKeyLength:
                raise ValidationError(
                    {"advertisement_key_hex": "The advertisement key must be exactly "
                     "28 bytes (56 hex characters)."})
        if self.private_key_hex:
            self.private_key_hex = self.private_key_hex.strip().lower()
            if len(bytes.fromhex(self.private_key_hex)) != AdvertisementKeyLength:
                raise ValidationError(
                    {"private_key_hex": "The private key must be exactly "
                     "28 bytes (56 hex characters)."})

    # ---- Full PKCS#8 PEM for macless-haystack / OpenHaystack tooling ----------
    def to_pem(self):
        """PEM-encoded private key (used by OpenHaystack-style imports)."""
        return keygen.private_key_to_pem(self.private_key)

    # ---- Byte accessors --------------------------------------------------------
    @property
    def advertisement_key(self):
        return bytes.fromhex(self.advertisement_key_hex)

    @property
    def private_key(self):
        return bytes.fromhex(self.private_key_hex)

    @property
    def hashed_key(self):
        """sha256 of the advertisement key (identifier used by Apple's fetch API)."""
        return hashlib.sha256(self.advertisement_key).digest()

    @property
    def hashed_key_b64(self):
        return base64.b64encode(self.hashed_key).decode("ascii")

    @property
    def advertisement_key_b64(self):
        return base64.b64encode(self.advertisement_key).decode("ascii")

    @property
    def private_key_b64(self):
        return base64.b64encode(self.private_key).decode("ascii")

    def macless_lines(self):
        """The three lines macless-haystack's ``*.keys`` file contains per device."""
        return [
            "Private key: {}".format(self.private_key_b64),
            "Advertisement key: {}".format(self.advertisement_key_b64),
            "Hashed adv key: {}".format(self.hashed_key_b64),
        ]

    @classmethod
    def keyfile(cls, devices):
        """Format a batch of devices as a macless-haystack ``*.keys`` file."""
        return "\n".join(line for device in devices for line in device.macless_lines()) + "\n"


class DeviceLocation(UUIDPrimaryKeyModel):
    """One decrypted location report stored for a device."""

    device = models.ForeignKey(
        Device, related_name="locations", on_delete=models.CASCADE)
    timestamp = models.DateTimeField(db_index=True, help_text="When the report was recorded.")
    latitude = models.FloatField()
    longitude = models.FloatField()
    horizontal_accuracy = models.FloatField(
        null=True, blank=True, help_text="Horizontal accuracy in meters.")
    status = models.IntegerField(
        default=0, help_text="Apple status byte (bits 6-7 carry battery level).")
    confidence = models.IntegerField(null=True, blank=True, help_text="Location confidence 1-3.")
    created_at = models.DateTimeField(auto_now_add=True)

    objects = DeviceLocationQuerySet.as_manager()

    class Meta:
        ordering = ["-timestamp"]
        constraints = [
            models.UniqueConstraint(
                fields=["device", "timestamp"], name="uniq_location_per_device_timestamp"),
        ]

    def __str__(self):
        return "{} @ {}".format(self.device, self.timestamp)

    BATTY_LEVELS = ("Full", "Medium", "Low", "Very Low")

    @property
    def battery_level(self):
        return self.BATTY_LEVELS[(self.status >> 6) & 0b11]