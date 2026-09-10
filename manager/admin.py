from django import forms
from django.contrib import admin

from manager import keygen
from manager.models import AppleAccount, Device, DeviceLocation


class AccountAdminForm(forms.ModelForm):
    password = forms.CharField(
        required=False, widget=forms.PasswordInput(render_value=False),
        label="Apple ID password",
        help_text="Stored encrypted. Leave empty to keep the current value.")

    class Meta:
        model = AppleAccount
        fields = ["user", "name", "email", "password", "active", "notes"]

    def save(self, commit=True):
        obj = super().save(commit=False)
        password = self.cleaned_data.get("password")
        if password:
            obj.set_password(password)
        if commit:
            obj.save()
        return obj


class DeviceInline(admin.TabularInline):
    model = Device
    extra = 0
    fields = ["name", "active", "broadcast_duration_sec", "sleep_duration_min"]
    can_delete = False


@admin.register(AppleAccount)
class AppleAccountAdmin(admin.ModelAdmin):
    form = AccountAdminForm
    list_display = ["name", "user", "email", "active", "password_is_set", "device_count", "updated_at"]
    list_filter = ["active", "user"]
    search_fields = ["name", "email", "user__username"]
    inlines = [DeviceInline]


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ["name", "account", "active", "broadcast_duration_sec",
                    "sleep_duration_min", "has_keypair", "updated_at"]
    list_filter = ["account", "active"]
    search_fields = ["name", "account__name"]
    fields = ["account", "name", "description", "active",
              "broadcast_duration_sec", "sleep_duration_min"]
    actions = ["generate_keypairs"]

    @admin.display(boolean=True, description="has keys")
    def has_keypair(self, obj):
        return bool(obj.private_key_hex and obj.advertisement_key_hex)

    @admin.action(description="Regenerate P-224 keypairs for selected devices")
    def generate_keypairs(self, request, queryset):
        count = 0
        for device in queryset:
            private_bytes, advertisement_bytes = keygen.generate_keypair()
            device.private_key_hex = private_bytes.hex()
            device.advertisement_key_hex = advertisement_bytes.hex()
            device.save(update_fields=["private_key_hex", "advertisement_key_hex", "updated_at"])
            count += 1
        self.message_user(request, "Regenerated keypairs for %d device(s)." % count)


@admin.register(DeviceLocation)
class DeviceLocationAdmin(admin.ModelAdmin):
    list_display = ["device", "timestamp", "latitude", "longitude",
                    "horizontal_accuracy", "battery_level"]
    list_filter = ["device__account", "device"]
    ordering = ["-timestamp"]
    search_fields = ["device__name"]
    readonly_fields = ["device", "timestamp", "latitude", "longitude",
                       "horizontal_accuracy", "status", "confidence", "created_at"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False