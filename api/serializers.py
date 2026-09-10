"""DRF serializers for the Find My manager API (v1)."""

from rest_framework import serializers

from manager import keygen
from manager.models import AppleAccount, Device, DeviceLocation


def _key_or_none(value, label):
    """Return a normalised (lowercase) 56-char hex key, or ``None`` if blank."""
    value = (value or "").strip().lower()
    if not value:
        return None
    try:
        keygen.hex_to_bytes(value, label)
        return value
    except ValueError as exc:
        raise serializers.ValidationError({label.split()[0]: str(exc)})


class AccountSerializer(serializers.ModelSerializer):
    """Apple accounts. The password is always write-only."""

    password = serializers.CharField(
        write_only=True, required=False, allow_blank=True, trim_whitespace=False,
        style={"input_type": "password"},
        help_text="Apple ID password, stored encrypted. Send to set/change; "
                  "omitted on read.",
    )
    device_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = AppleAccount
        fields = [
            "id", "name", "email", "password", "active", "notes",
            "created_at", "updated_at", "last_fetch_at", "last_fetch_status",
            "last_fetch_message", "device_count",
        ]
        read_only_fields = [
            "created_at", "updated_at", "last_fetch_at", "last_fetch_status",
            "last_fetch_message", "device_count",
        ]

    def validate(self, attrs):
        # Keep the stored password unless a new one is explicitly sent in the
        # request body (handled in create()/update() by checking membership).
        return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop("password", "") or ""
        account = AppleAccount(**validated_data)
        account.set_password(password)
        account.save()
        return account

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        done = super().update(instance, validated_data)
        if password is not None:
            done.set_password(password)
            done.save(update_fields=["password_encrypted", "updated_at"])
        return done


class DeviceSerializer(serializers.ModelSerializer):
    """Devices. Secret keys are never returned here; use /devices/<pk>/keys/.

    On create, send ``private_key_hex`` + ``advertisement_key_hex`` to import an
    existing keypair, or send neither to auto-generate a fresh P-224 pair.
    On update, omit both to keep the current keypair untouched.
    """

    account = serializers.PrimaryKeyRelatedField(queryset=AppleAccount.objects.none())
    private_key_hex = serializers.CharField(
        write_only=True, required=False, allow_blank=True, trim_whitespace=False)
    advertisement_key_hex = serializers.CharField(
        write_only=True, required=False, allow_blank=True, trim_whitespace=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        user = getattr(request, "user", None)
        self.fields["account"].queryset = AppleAccount.objects.for_user(user)

    class Meta:
        model = Device
        fields = [
            "id", "account", "name", "description", "active",
            "broadcast_duration_sec", "sleep_duration_min",
            "private_key_hex", "advertisement_key_hex",
            "has_keypair", "created_at", "updated_at",
        ]
        read_only_fields = ["has_keypair", "created_at", "updated_at"]
        extra_kwargs = {
            "broadcast_duration_sec": {"min_value": 1, "max_value": 3600},
            "sleep_duration_min": {"min_value": 1, "max_value": 1440},
        }

    has_keypair = serializers.SerializerMethodField()

    def get_has_keypair(self, obj):
        return bool(obj.private_key_hex and obj.advertisement_key_hex)

    def validate(self, attrs):
        private_present = attrs.get("private_key_hex") not in (None, "")
        public_present = attrs.get("advertisement_key_hex") not in (None, "")

        private = _key_or_none(attrs.get("private_key_hex"), "private key") if private_present else None
        public = _key_or_none(attrs.get("advertisement_key_hex"), "advertisement key") if public_present else None

        if private_present or public_present:
            if not (private and public):
                raise serializers.ValidationError(
                    {"keypair": "Both private_key_hex and advertisement_key_hex "
                     "are required to import a keypair."})
            try:
                keygen.validate_keypair(private, public)
            except ValueError as exc:
                raise serializers.ValidationError({"keypair": str(exc)})
            attrs["private_key_hex"] = private
            attrs["advertisement_key_hex"] = public
        else:
            attrs.pop("private_key_hex", None)
            attrs.pop("advertisement_key_hex", None)
        return attrs

    def create(self, validated_data):
        device = Device(**validated_data)
        if not (device.private_key_hex and device.advertisement_key_hex):
            private_bytes, advertisement_bytes = keygen.generate_keypair()
            device.private_key_hex = private_bytes.hex()
            device.advertisement_key_hex = advertisement_bytes.hex()
        device.save()
        return device

    def update(self, instance, validated_data):
        # Keys intentionally untouched unless the caller supplies a full pair.
        return super().update(instance, validated_data)


class DeviceKeysSerializer(serializers.Serializer):
    """Evaluation of a device's keypair: hex + base64 + derived values."""

    advertisement_key_hex = serializers.SerializerMethodField()
    private_key_hex = serializers.SerializerMethodField()
    advertisement_key_b64 = serializers.SerializerMethodField()
    private_key_b64 = serializers.SerializerMethodField()
    hashed_key_b64 = serializers.SerializerMethodField()

    def _ready(self, obj):
        return bool(obj.private_key_hex and obj.advertisement_key_hex)

    def get_advertisement_key_hex(self, obj):
        return obj.advertisement_key_hex if self._ready(obj) else None

    def get_private_key_hex(self, obj):
        return obj.private_key_hex if self._ready(obj) else None

    def get_advertisement_key_b64(self, obj):
        return obj.advertisement_key_b64 if self._ready(obj) else None

    def get_private_key_b64(self, obj):
        return obj.private_key_b64 if self._ready(obj) else None

    def get_hashed_key_b64(self, obj):
        return obj.hashed_key_b64 if self._ready(obj) else None


class DeviceLocationSerializer(serializers.ModelSerializer):
    device = serializers.PrimaryKeyRelatedField(read_only=True)
    battery_level = serializers.CharField(read_only=True)

    class Meta:
        model = DeviceLocation
        fields = [
            "id", "device", "timestamp", "latitude", "longitude",
            "horizontal_accuracy", "status", "confidence",
            "battery_level", "created_at",
        ]
        read_only_fields = fields


class MapMarkerSerializer(serializers.Serializer):
    device = serializers.PrimaryKeyRelatedField(read_only=True)
    device_name = serializers.CharField(source="device.name", read_only=True)
    account = serializers.PrimaryKeyRelatedField(
        source="device.account", read_only=True)
    account_name = serializers.CharField(source="device.account.name", read_only=True)
    latitude = serializers.FloatField(read_only=True)
    longitude = serializers.FloatField(read_only=True)
    timestamp = serializers.DateTimeField(read_only=True)
    horizontal_accuracy = serializers.FloatField(read_only=True)
    battery_level = serializers.CharField(read_only=True)
    url = serializers.CharField(read_only=True)


class ExportSerializer(serializers.Serializer):
    device = serializers.UUIDField(read_only=True)
    fmt = serializers.CharField(read_only=True)
    filename = serializers.CharField(read_only=True)
    content_type = serializers.CharField(read_only=True)
    content = serializers.CharField(read_only=True)


class KeyFileSerializer(serializers.Serializer):
    filename = serializers.CharField(read_only=True)
    content_type = serializers.CharField(read_only=True)
    content = serializers.CharField(read_only=True)