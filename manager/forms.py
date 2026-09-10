"""Forms for the Find My manager."""

from django import forms
from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError
from django.urls import NoReverseMatch, reverse
from django.utils.safestring import mark_safe

from manager import keygen
from manager.models import AppleAccount, Device


class ManagerAuthenticationForm(AuthenticationForm):
    """Username or email, and block allauth signups that still need verification."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].label = "Username or email"
        self.fields["username"].widget.attrs["autocomplete"] = "username"
        try:
            reset_url = reverse("account_reset_password")
        except NoReverseMatch:
            reset_url = ""
        if reset_url:
            self.fields["password"].help_text = mark_safe(
                '<a href="%s">Forgot your password?</a>' % reset_url)

    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user)
        if getattr(settings, "ACCOUNT_EMAIL_VERIFICATION", "") != "mandatory":
            return
        from allauth.account.models import EmailAddress

        addresses = EmailAddress.objects.filter(user=user)
        if addresses.exists() and not addresses.filter(verified=True).exists():
            raise ValidationError(
                "Confirm your email address before signing in. "
                "Check your inbox for the verification link.",
                code="unverified",
            )


class AccountForm(forms.ModelForm):
    password = forms.CharField(
        label="Apple ID password",
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Stored encrypted; used by the macless-haystack container "
                  "(config.ini appleid_pass). Leave empty to keep unchanged.",
    )

    class Meta:
        model = AppleAccount
        fields = ["name", "email", "password", "active", "notes"]

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        self.fields["password"].widget.attrs["autocomplete"] = "new-password"

    def save(self, commit=True):
        account = super().save(commit=False)
        if self.user is not None and not account.user_id:
            account.user = self.user
        password = self.cleaned_data.get("password")
        if password:
            account.set_password(password)
        elif self.instance and not self.instance.pk:
            # Brand-new account without a password: nothing to store.
            account.set_password("")
        if commit:
            account.save()
        return account


_KEY_SOURCE_CHOICES = [("generate", "Generate a new P-224 keypair"), ("import", "Import an existing keypair")]


class DeviceForm(forms.ModelForm):
    key_source = forms.ChoiceField(
        choices=_KEY_SOURCE_CHOICES, initial="generate", widget=forms.RadioSelect)
    advertisement_key_hex = forms.CharField(
        label="Advertisement key (hex)", required=False,
        widget=forms.TextInput(attrs={"placeholder": "56 hex chars (28-byte P-224 public x-coordinate)"}),
        help_text="Only needed when 'import' is selected.",
    )
    private_key_hex = forms.CharField(
        label="Private key (hex)", required=False,
        widget=forms.TextInput(attrs={"placeholder": "56 hex chars"}),
        help_text="Only needed when 'import' is selected.",
    )

    class Meta:
        model = Device
        fields = [
            "account", "name", "description", "key_source",
            "advertisement_key_hex", "private_key_hex",
            "active", "broadcast_duration_sec", "sleep_duration_min",
        ]

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user is not None:
            self.fields["account"].queryset = AppleAccount.objects.for_user(user)

    def clean(self):
        cleaned = super().clean()
        key_source = cleaned.get("key_source")
        if key_source == "import":
            adv = cleaned.get("advertisement_key_hex")
            priv = cleaned.get("private_key_hex")
            missing = []
            if not adv:
                missing.append("advertisement_key_hex")
            if not priv:
                missing.append("private_key_hex")
            if missing:
                for name in missing:
                    self.add_error(name, "This field is required when importing a keypair.")
                return cleaned
            try:
                keygen.hex_to_bytes(adv, "advertisement key")
            except ValueError as exc:
                self.add_error("advertisement_key_hex", str(exc))
            try:
                keygen.hex_to_bytes(priv, "private key")
            except ValueError as exc:
                self.add_error("private_key_hex", str(exc))
            if not self.errors:
                try:
                    keygen.validate_keypair(priv, adv)
                except ValueError as exc:
                    self.add_error("private_key_hex", str(exc))
        return cleaned

    def save(self, commit=True):
        device = super().save(commit=False)
        if self.cleaned_data.get("key_source") == "generate":
            private_bytes, advertisement_bytes = keygen.generate_keypair()
            device.private_key_hex = private_bytes.hex()
            device.advertisement_key_hex = advertisement_bytes.hex()
        if commit:
            device.save()
        return device


class MicropythonExportForm(forms.Form):
    broadcast_duration_sec = forms.IntegerField(
        label="Broadcast duration (seconds)", min_value=1, max_value=3600, initial=10)
    sleep_duration_min = forms.IntegerField(
        label="Deep sleep duration (minutes)", min_value=1, max_value=1440, initial=5)


class FirmwareExportForm(forms.Form):
    broadcast_duration_sec = forms.IntegerField(
        label="Beacon window (seconds)", min_value=1, max_value=3600, initial=10,
        help_text="How long the radio advertises per cycle.")
    sleep_duration_min = forms.IntegerField(
        label="Delay between beacons (minutes)", min_value=1, max_value=1440, initial=5,
        help_text="Idle time between cycles.")