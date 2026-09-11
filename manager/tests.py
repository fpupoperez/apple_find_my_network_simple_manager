from datetime import datetime, timezone as dt_timezone
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone
from unittest.mock import patch

from manager import keygen, micropython, esp_idf, arduino
from manager import tasks
from manager.models import AppleAccount, Device, DeviceLocation

User = get_user_model()


def _owner(username="owner", email=None):
    return User.objects.create_user(
        username, email or "{}@example.com".format(username), "secret123")


class KeygenTests(TestCase):
    def test_generate_keypair_shapes(self):
        private_bytes, advertisement_bytes = keygen.generate_keypair()
        self.assertEqual(len(private_bytes), 28)
        self.assertEqual(len(advertisement_bytes), 28)

    def test_derive_public_matches_generated(self):
        private_bytes, advertisement_bytes = keygen.generate_keypair()
        self.assertEqual(keygen.derive_public_x(private_bytes), advertisement_bytes)

    def test_invalid_hex_rejected(self):
        with self.assertRaises(ValueError):
            keygen.hex_to_bytes("zz", "key")
        with self.assertRaises(ValueError):
            keygen.hex_to_bytes("deadbeef", "key")

    def test_keypair_validation(self):
        private, public = keygen.generate_keypair()
        keygen.validate_keypair(private.hex(), public.hex())
        other_private, _ = keygen.generate_keypair()
        with self.assertRaises(ValueError):
            keygen.validate_keypair(other_private.hex(), public.hex())


class DeviceModelTests(TestCase):
    def setUp(self):
        self.account = AppleAccount.objects.create(
            user=_owner(), name="Home", email="home@example.com", active=True)
        self.account.set_password("hunter2")
        self.account.save()
        private, public = keygen.generate_keypair()
        self.device = Device.objects.create(
            account=self.account, name="car",
            private_key_hex=private.hex(), advertisement_key_hex=public.hex())

    def test_primary_keys_are_uuids(self):
        import uuid
        uuid.UUID(str(self.account.id))
        uuid.UUID(str(self.device.id))

    def test_password_encrypted_at_rest(self):
        raw = AppleAccount.objects.get(pk=self.account.pk).password_encrypted
        self.assertNotEqual(raw, "hunter2")
        self.assertTrue(raw.startswith("crypt:"))
        self.assertEqual(self.account.get_password(), "hunter2")

    def test_hashed_key_matches_sha256(self):
        import hashlib
        self.assertEqual(
            self.device.hashed_key,
            hashlib.sha256(self.device.advertisement_key).digest())

    def test_macless_lines(self):
        lines = self.device.macless_lines()
        self.assertEqual(len(lines), 3)
        self.assertIn("Private key: ", lines[0])
        self.assertIn("Advertisement key: ", lines[1])
        self.assertIn("Hashed adv key: ", lines[2])

    def test_devices_unique_per_account(self):
        with self.assertRaises(Exception):
            Device.objects.create(account=self.account, name="car",
                                  private_key_hex="0" * 56,
                                  advertisement_key_hex="1" * 56)


class MicropythonGenerationTests(TestCase):
    def setUp(self):
        self.account = AppleAccount.objects.create(
            user=_owner(), name="Home", email="h@example.com")
        private, public = keygen.generate_keypair()
        self.device = Device.objects.create(
            account=self.account, name="bag", broadcast_duration_sec=5, sleep_duration_min=7,
            private_key_hex=private.hex(), advertisement_key_hex=public.hex())

    def test_generate_main_py_embeds_key(self):
        source = micropython.generate_main_py(self.device)
        for b in self.device.advertisement_key:
            self.assertIn("0x{:02x}".format(b), source)
        self.assertIn("BROADCAST_DURATION_SEC = 5", source)
        self.assertIn("SLEEP_DURATION_MIN = 7", source)
        self.assertIn('b"\\x12\\x19"', source)
        self.assertNotIn("extend([", source)
        self.assertIn("machine.deepsleep", source)

    def test_generate_main_py_overrides(self):
        source = micropython.generate_main_py(self.device, broadcast_duration_sec=3, sleep_duration_min=2)
        self.assertIn("BROADCAST_DURATION_SEC = 3", source)
        self.assertIn("SLEEP_DURATION_MIN = 2", source)

    def test_payload_is_31_bytes(self):
        # OpenHaystack "offline finding" advertisement that fits the 31-byte
        # legacy BLE limit: single manufacturer data AD, no Flags AD.
        key = bytes(range(28))
        payload = bytearray()
        payload.append(0x1E)
        payload.append(0xFF)
        payload.extend([0x4C, 0x00])
        payload.extend([0x12, 0x19])
        payload.append(0x00)
        payload.extend(key[6:28])
        payload.append(key[0] >> 6)
        payload.append(0x00)
        self.assertEqual(len(payload), 31)
        self.assertEqual(bytes(payload[:7]), bytes([0x1E, 0xFF, 0x4C, 0x00, 0x12, 0x19, 0x00]))

    def test_generated_payload_function_produces_valid_beacon(self):
        # Run the actual generate_payload()/ble_address_from_key() emitted in
        # the download to verify they build the 31-byte OpenHaystack beacon
        # and that the full 28-byte key reassembles from address + payload
        # (uses only MicroPython-compatible bytearray operations).
        import ast

        from manager import micropython

        source = micropython.generate_main_py(self.device)
        tree = ast.parse(source)
        fns = [node for node in tree.body
               if isinstance(node, ast.FunctionDef)
               and node.name in ("generate_payload", "ble_address_from_key")]
        self.assertEqual(len(fns), 2)
        namespace = {}
        exec(compile(ast.Module(body=fns, type_ignores=[]), "<generated>", "exec"), namespace)

        key = bytes(range(28))
        payload = namespace["generate_payload"](key)
        addr = namespace["ble_address_from_key"](key)

        self.assertEqual(len(payload), 31)
        self.assertEqual(bytes(payload[:7]), b"\x1e\xff\x4c\x00\x12\x19\x00")
        self.assertEqual(bytes(payload[7:29]), bytes(range(6, 28)))
        self.assertEqual(payload[29], key[0] >> 6)
        self.assertEqual(payload[30], 0x00)
        self.assertEqual(addr[0] & 0b11000000, 0b11000000)

        # reassemble the full key the way the Find My server does
        first = ((addr[0] & 0x3F) | (payload[29] << 6))
        reassembled = bytes([first]) + bytes(addr[1:6]) + bytes(payload[7:29])
        self.assertEqual(reassembled, key)


class FirmwareGenerationTests(TestCase):
    def setUp(self):
        self.account = AppleAccount.objects.create(
            user=_owner(), name="Home", email="h@example.com")
        private, public = keygen.generate_keypair()
        self.device = Device.objects.create(
            account=self.account, name="bag", broadcast_duration_sec=5, sleep_duration_min=7,
            private_key_hex=private.hex(), advertisement_key_hex=public.hex())

    def test_generate_firmware_embeds_key(self):
        source = esp_idf.generate_firmware_c(self.device)
        for b in self.device.advertisement_key:
            self.assertIn("0x{:02x}".format(b), source)
        self.assertIn("esp_ble_gap_set_rand_addr", source)
        self.assertIn("#define BEACON_WINDOW_S   5", source)
        self.assertIn("#define BEACON_DELAY_S    %d" % (7 * 60), source)

    def test_generate_firmware_overrides(self):
        source = esp_idf.generate_firmware_c(self.device, broadcast_duration_sec=3,
                                             sleep_duration_min=2)
        self.assertIn("#define BEACON_WINDOW_S   3", source)
        self.assertIn("#define BEACON_DELAY_S    %d" % (2 * 60), source)

    def test_firmware_rebuilds_openhaystack_beacon(self):
        # Extract the embedded key from the C source, re-derive the beacon
        # layout the generated C builds, then check the full key reassembles
        # the way the Find My server does (addr[0:6] + payload[6:28] + bits).
        import re

        source = esp_idf.generate_firmware_c(self.device)
        m = re.search(r"public_key\[28\] = \{(.*?)\};", source, re.S)
        self.assertIsNotNone(m)
        values = [int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", m.group(1))]
        self.assertEqual(bytes(values), self.device.advertisement_key)

        adv = bytearray(31)                                  # mirror set_payload_from_key()
        adv[:7] = bytes([0x1E, 0xFF, 0x4C, 0x00, 0x12, 0x19, 0x00])
        adv[7:29] = bytes(values[6:28])
        adv[29] = values[0] >> 6
        adv[30] = 0x00
        self.assertEqual(len(adv), 31)                       # fits the legacy limit
        self.assertEqual(bytes(adv[:7]), b"\x1e\xff\x4c\x00\x12\x19\x00")

        addr = bytearray(values[0:6])                        # mirror set_addr_from_key()
        addr[0] |= 0xC0
        self.assertEqual(addr[0] & 0b11000000, 0b11000000)

        first = ((addr[0] & 0x3F) | (adv[29] << 6))
        reassembled = bytes([first]) + bytes(addr[1:6]) + bytes(adv[7:29])
        self.assertEqual(reassembled, self.device.advertisement_key)


class ArduinoSketchGenerationTests(TestCase):
    def setUp(self):
        self.account = AppleAccount.objects.create(
            user=_owner(), name="Home", email="h@example.com")
        private, public = keygen.generate_keypair()
        self.device = Device.objects.create(
            account=self.account, name="bag", broadcast_duration_sec=5, sleep_duration_min=7,
            private_key_hex=private.hex(), advertisement_key_hex=public.hex())

    def test_generate_sketch_embeds_key(self):
        source = arduino.generate_sketch_ino(self.device)
        for b in self.device.advertisement_key:
            self.assertIn("0x{:02x}".format(b), source)
        self.assertIn("btStart()", source)
        self.assertIn('esp_ble_gap_register_callback', source)
        self.assertIn("esp_ble_gap_set_rand_addr", source)
        self.assertIn("esp32-hal-alloc-ble-mem.h", source)
        self.assertNotIn("psram", source)
        self.assertIn("#define BEACON_WINDOW_S   5", source)
        self.assertIn("#define BEACON_DELAY_S    %d" % (7 * 60), source)

    def test_generate_sketch_overrides(self):
        source = arduino.generate_sketch_ino(self.device, broadcast_duration_sec=3,
                                             sleep_duration_min=2)
        self.assertIn("#define BEACON_WINDOW_S   3", source)
        self.assertIn("#define BEACON_DELAY_S    %d" % (2 * 60), source)

    def test_sketch_rebuilds_openhaystack_beacon(self):
        import re

        source = arduino.generate_sketch_ino(self.device)
        m = re.search(r"public_key\[28\] = \{(.*?)\};", source, re.S)
        self.assertIsNotNone(m)
        values = [int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", m.group(1))]
        self.assertEqual(bytes(values), self.device.advertisement_key)

        adv = bytearray(31)                                  # mirror set_payload_from_key()
        adv[:7] = bytes([0x1E, 0xFF, 0x4C, 0x00, 0x12, 0x19, 0x00])
        adv[7:29] = bytes(values[6:28])
        adv[29] = values[0] >> 6
        adv[30] = 0x00
        self.assertEqual(len(adv), 31)                       # fits the legacy limit
        self.assertEqual(bytes(adv[:7]), b"\x1e\xff\x4c\x00\x12\x19\x00")

        addr = bytearray(values[0:6])                        # mirror set_addr_from_key()
        addr[0] |= 0xC0
        self.assertEqual(addr[0] & 0b11000000, 0b11000000)

        first = ((addr[0] & 0x3F) | (adv[29] << 6))
        reassembled = bytes([first]) + bytes(addr[1:6]) + bytes(adv[7:29])
        self.assertEqual(reassembled, self.device.advertisement_key)


class NativeExportStringHygieneTests(TestCase):
    """C string literals in the generated firmware must not contain raw newlines
    (the ``\\n`` in templates stays a two-character escape, so the output is
    valid C; regressions here break compilation with 'missing terminating
    quote' / naked newline errors)."""

    def _check_generated_source(self, source):
        import re
        for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', source):
            self.assertNotIn("\n", m.group(1),
                             "C string literal contains a real newline: %r" % m.group(0))
        self.assertNotIn("\r", source)

    def _device(self):
        from manager.models import AppleAccount, Device
        from manager import keygen
        account = AppleAccount.objects.create(
            user=_owner(), name="Home", email="h@example.com")
        private, public = keygen.generate_keypair()
        return Device.objects.create(
            account=account, name="bag",
            private_key_hex=private.hex(), advertisement_key_hex=public.hex())

    def test_arduino_sketch_strings(self):
        self._check_generated_source(arduino.generate_sketch_ino(self._device()))

    def test_esp_idf_firmware_strings(self):
        self._check_generated_source(esp_idf.generate_firmware_c(self._device()))


class AuthTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="viewer", email="viewer@example.com", password="secret123")

    def test_anonymous_redirected_to_login(self):
        resp = self.client.get(reverse("manager:dashboard"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, "/login/?next=/")
        resp = self.client.get(reverse("manager:device_list"))
        self.assertEqual(resp.status_code, 302)

    def test_login_page(self):
        resp = self.client.get(reverse("manager:login"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Sign in")

    def test_operations_nav_hidden_when_anonymous(self):
        resp = self.client.get(reverse("manager:login"))
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, 'href="%s"' % reverse("manager:dashboard"))
        self.assertNotContains(resp, 'href="%s"' % reverse("manager:account_list"))
        self.assertNotContains(resp, 'href="%s"' % reverse("manager:device_list"))
        self.assertNotContains(resp, 'href="%s"' % reverse("manager:map"))
        self.assertNotContains(resp, 'href="%s"' % reverse("manager:device_create"))
        self.assertContains(resp, 'href="%s"' % reverse("manager:login"))

    def test_operations_nav_visible_when_logged_in(self):
        self.client.force_login(self.user)
        resp = self.client.get(reverse("manager:dashboard"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'href="%s"' % reverse("manager:dashboard"))
        self.assertContains(resp, 'href="%s"' % reverse("manager:account_list"))
        self.assertContains(resp, 'href="%s"' % reverse("manager:device_list"))
        self.assertContains(resp, 'href="%s"' % reverse("manager:map"))
        self.assertContains(resp, 'href="%s"' % reverse("manager:device_create"))
        self.assertContains(resp, 'id="userMenu"')
        self.assertContains(resp, 'data-bs-toggle="dropdown"')
        self.assertContains(resp, 'href="%s"' % reverse("manager:profile"))
        self.assertContains(resp, 'action="%s"' % reverse("manager:logout"))
        self.assertContains(resp, self.user.username)

    def test_login_flow(self):
        resp = self.client.post(reverse("manager:login"), {
            "username": "viewer", "password": "secret123"})
        self.assertRedirects(resp, "/")
        resp = self.client.get(reverse("manager:dashboard"))
        self.assertEqual(resp.status_code, 200)

    def test_login_rejects_bad_credentials(self):
        resp = self.client.post(reverse("manager:login"), {
            "username": "viewer", "password": "wrong"})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "correct username and password")

    def test_login_accepts_email(self):
        resp = self.client.post(reverse("manager:login"), {
            "username": self.user.email, "password": "secret123"})
        self.assertRedirects(resp, "/")

    def test_login_page_links_to_signup(self):
        resp = self.client.get(reverse("manager:login"))
        self.assertContains(resp, reverse("account_signup"))
        self.assertContains(resp, "Username or email")
        self.assertContains(resp, reverse("account_reset_password"))
        self.assertContains(resp, "Forgot your password?")

    def test_signup_requires_unique_verified_email(self):
        from allauth.account.models import EmailAddress
        from django.core import mail

        signup = reverse("account_signup")
        page = self.client.get(signup)
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "email")

        created = self.client.post(signup, {
            "username": "newbie",
            "email": "newbie@example.com",
            "password1": "a-strong-pass-123",
            "password2": "a-strong-pass-123",
        })
        self.assertEqual(created.status_code, 302)
        user = get_user_model().objects.get(username="newbie")
        address = EmailAddress.objects.get(user=user, email="newbie@example.com")
        self.assertFalse(address.verified)
        self.assertEqual(len(mail.outbox), 1)

        blocked = self.client.post(reverse("manager:login"), {
            "username": "newbie", "password": "a-strong-pass-123"})
        self.assertEqual(blocked.status_code, 200)
        self.assertContains(blocked, "Confirm your email")

        duplicate = self.client.post(signup, {
            "username": "othernew",
            "email": "newbie@example.com",
            "password1": "a-strong-pass-123",
            "password2": "a-strong-pass-123",
        })
        self.assertEqual(duplicate.status_code, 200)
        self.assertFalse(get_user_model().objects.filter(username="othernew").exists())

        import re
        match = re.search(r"/account/confirm-email/([^/\s]+)/", mail.outbox[0].body)
        self.assertIsNotNone(match)
        verified = self.client.get(reverse("account_confirm_email", args=[match.group(1)]))
        if verified.status_code == 200 and verified.context.get("form"):
            verified = self.client.post(reverse(
                "account_confirm_email", args=[match.group(1)]), {"key": match.group(1)})
        self.assertIn(verified.status_code, (200, 302))
        address.refresh_from_db()
        self.assertTrue(address.verified)
        self.client.logout()
        logged_in = self.client.post(reverse("manager:login"), {
            "username": "newbie@example.com", "password": "a-strong-pass-123"})
        self.assertRedirects(logged_in, "/")

    def test_logout(self):
        self.client.force_login(self.user)
        resp = self.client.post(reverse("manager:logout"))
        self.assertRedirects(resp, "/login/")
        self.assertEqual(self.client.get(reverse("manager:dashboard")).status_code, 302)

    def test_api_no_session_required(self):
        resp = self.client.get("/api/v1/devices/")
        self.assertIn(resp.status_code, (401, 403))

    def test_favicon_public(self):
        resp = self.client.get("/favicon.ico")
        self.assertEqual(resp.status_code, 301)

    def test_admin_and_api_templates_omit_django_branding(self):
        resp = self.client.get("/admin/login/")
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "Django")
        self.assertContains(resp, "Find My manager")
        staff = get_user_model().objects.create_user(
            username="admin", email="admin@example.com", password="secret123",
            is_staff=True, is_superuser=True)
        self.client.force_login(staff)
        resp = self.client.get("/admin/")
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "Django")
        self.assertContains(resp, "Find My manager")
        resp = self.client.get("/api/v1/", HTTP_ACCEPT="text/html")
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "Django")
        self.assertNotContains(resp, "REST framework")
        self.assertContains(resp, "Find My manager API")

    def test_profile_requires_login(self):
        resp = self.client.get(reverse("manager:profile"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login/", resp.url)

    def test_profile_shows_user_and_allauth_operations(self):
        self.client.force_login(self.user)
        resp = self.client.get(reverse("manager:profile"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.user.username)
        self.assertContains(resp, self.user.email)
        self.assertContains(resp, reverse("account_email"))
        self.assertContains(resp, reverse("account_change_password"))
        self.assertContains(resp, reverse("account_reset_password"))
        self.assertContains(resp, reverse("mfa_index"))
        self.assertContains(resp, reverse("account_reauthenticate"))
        self.assertContains(resp, reverse("account_logout"))
        self.assertContains(resp, 'href="%s"' % reverse("manager:profile"))
        email_page = self.client.get(reverse("account_email"))
        self.assertEqual(email_page.status_code, 200)
        self.assertContains(email_page, "btn btn-primary")
        self.assertContains(email_page, "form-check")
        self.assertContains(email_page, "card-body")
        self.assertContains(email_page, "bootstrap.min.css")
        mfa_page = self.client.get(reverse("mfa_index"))
        self.assertEqual(mfa_page.status_code, 200)
        self.assertContains(mfa_page, "allauth-panel")
        self.assertContains(mfa_page, "btn btn-primary")
        password_page = self.client.get(reverse("account_change_password"))
        self.assertEqual(password_page.status_code, 200)
        self.assertContains(password_page, "form-control")
        self.assertContains(password_page, "btn btn-primary")
        login_page = self.client.get(reverse("account_login"))
        self.assertIn(login_page.status_code, (200, 302))
        guest = self.client_class()
        guest_login = guest.get(reverse("account_login"))
        self.assertEqual(guest_login.status_code, 200)
        self.assertContains(guest_login, "form-control")
        self.assertContains(guest_login, "btn btn-primary")
        self.assertContains(guest_login, "bootstrap.min.css")


class ViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="viewer", email="viewer@example.com", password="secret123")
        self.client.force_login(self.user)
        self.account = AppleAccount.objects.create(
            user=self.user, name="Home", email="h@example.com")
        self.account.set_password("hunter2")
        self.account.save()
        private, public = keygen.generate_keypair()
        self.device = Device.objects.create(
            account=self.account, name="car",
            private_key_hex=private.hex(), advertisement_key_hex=public.hex())

    def test_dashboard(self):
        resp = self.client.get(reverse("manager:dashboard"))
        self.assertEqual(resp.status_code, 200)

    def test_favicon_served(self):
        # The test client does not serve static files; assert the redirect and
        # that the icon actually exists in the static tree.
        from django.contrib.staticfiles import finders
        resp = self.client.get("/favicon.ico")
        self.assertEqual(resp.status_code, 301)
        self.assertIn("/static/manager/img/favicon.ico", resp["Location"])
        self.assertIsNotNone(finders.find("manager/img/favicon.ico"))

    def test_account_list_shows_device_count(self):
        # device_count is a model @property; the view must not clash with it
        # (regression: annotate(device_count=...) raised AttributeError).
        resp = self.client.get(reverse("manager:account_list"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.account.name)
        self.assertContains(resp, "1")

    def test_device_detail(self):
        url = reverse("manager:device_detail", args=[self.device.pk])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.device.advertisement_key_hex)

    def test_device_detail_keeps_latest_only(self):
        later = timezone.now()
        earlier = later - timezone.timedelta(hours=1)
        DeviceLocation.objects.create(device=self.device, timestamp=earlier,
                                      latitude=40.0, longitude=-3.5, horizontal_accuracy=12.0)
        DeviceLocation.objects.create(device=self.device, timestamp=later,
                                      latitude=41.0, longitude=-2.5, horizontal_accuracy=8.0)
        resp = self.client.get(reverse("manager:device_detail", args=[self.device.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Showing the most recent report")
        self.assertContains(resp, "View full history")
        self.assertNotContains(resp, "2 reports")

    def test_device_history(self):
        later = timezone.now()
        earlier = later - timezone.timedelta(hours=1)
        DeviceLocation.objects.create(device=self.device, timestamp=earlier,
                                      latitude=40.0, longitude=-3.5, horizontal_accuracy=12.0)
        DeviceLocation.objects.create(device=self.device, timestamp=later,
                                      latitude=41.0, longitude=-2.5, horizontal_accuracy=8.0)
        resp = self.client.get(reverse("manager:device_history", args=[self.device.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Location history")
        self.assertContains(resp, "2 reports")
        self.assertContains(resp, "history-table")
        self.assertContains(resp, 'id="date-from"')
        self.assertContains(resp, 'id="date-to"')
        data_url = reverse("manager:device_history_data", args=[self.device.pk])
        self.assertContains(resp, data_url)
        payload = self.client.get(data_url, {
            "draw": 1, "start": 0, "length": 25,
            "order[0][column]": 0, "order[0][dir]": "desc",
        })
        self.assertEqual(payload.status_code, 200)
        body = payload.json()
        self.assertEqual(body["recordsTotal"], 2)
        self.assertEqual(len(body["data"]), 2)
        # newest report first
        first_row = "".join(str(cell) for cell in body["data"][0])
        second_row = "".join(str(cell) for cell in body["data"][1])
        self.assertIn("41.000000", first_row)
        self.assertIn("40.000000", second_row)

    def test_device_history_paginates(self):
        base = timezone.now()
        for i in range(30):
            DeviceLocation.objects.create(
                device=self.device,
                timestamp=base + timezone.timedelta(minutes=i),
                latitude=40.0 + float(i), longitude=-3.0)
        page_url = reverse("manager:device_history", args=[self.device.pk])
        data_url = reverse("manager:device_history_data", args=[self.device.pk])
        self.assertEqual(self.client.get(page_url).status_code, 200)
        page1 = self.client.get(data_url, {
            "draw": 1, "start": 0, "length": 25,
            "order[0][column]": 0, "order[0][dir]": "desc",
        })
        self.assertEqual(page1.status_code, 200)
        body1 = page1.json()
        self.assertEqual(body1["recordsTotal"], 30)
        self.assertEqual(len(body1["data"]), 25)
        page2 = self.client.get(data_url, {
            "draw": 2, "start": 25, "length": 25,
            "order[0][column]": 0, "order[0][dir]": "desc",
        })
        self.assertEqual(page2.status_code, 200)
        body2 = page2.json()
        self.assertEqual(len(body2["data"]), 5)
        # empty / oversized page is still valid JSON
        empty = self.client.get(data_url, {
            "draw": 3, "start": 1000, "length": 25,
        })
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.json()["data"], [])

    def test_device_history_filters_by_date(self):
        older = datetime(2024, 1, 10, 12, 0, tzinfo=dt_timezone.utc)
        newer = datetime(2024, 3, 20, 12, 0, tzinfo=dt_timezone.utc)
        DeviceLocation.objects.create(
            device=self.device, timestamp=older,
            latitude=40.0, longitude=-3.5)
        DeviceLocation.objects.create(
            device=self.device, timestamp=newer,
            latitude=41.0, longitude=-2.5)
        data_url = reverse("manager:device_history_data", args=[self.device.pk])
        params = {
            "draw": 1, "start": 0, "length": 25,
            "order[0][column]": 0, "order[0][dir]": "desc",
        }
        january = self.client.get(data_url, {**params, "date_from": "2024-01-01",
                                            "date_to": "2024-01-31"})
        self.assertEqual(january.status_code, 200)
        body = january.json()
        self.assertEqual(body["recordsTotal"], 2)
        self.assertEqual(body["recordsFiltered"], 1)
        self.assertEqual(len(body["data"]), 1)
        self.assertIn("40.000000", "".join(str(cell) for cell in body["data"][0]))

        from_march = self.client.get(data_url, {**params, "date_from": "2024-03-01"})
        self.assertEqual(from_march.json()["recordsFiltered"], 1)
        self.assertIn(
            "41.000000",
            "".join(str(cell) for cell in from_march.json()["data"][0]))

        invalid = self.client.get(data_url, {**params, "date_from": "not-a-date"})
        self.assertEqual(invalid.json()["recordsFiltered"], 2)

    def test_export_micropython_download(self):
        url = reverse("manager:device_export_micropython", args=[self.device.pk])
        resp = self.client.post(url, {"broadcast_duration_sec": 3, "sleep_duration_min": 2})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "text/x-python")
        body = resp.content.decode()
        self.assertIn("BROADCAST_DURATION_SEC = 3", body)
        self.assertIn("Content-Disposition", resp.headers)

    def test_export_micropython_page(self):
        url = reverse("manager:device_export_micropython", args=[self.device.pk])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Preview")

    def test_export_firmware_page(self):
        url = reverse("manager:device_export_firmware", args=[self.device.pk])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "main.c")
        self.assertContains(resp, "Export ESP-IDF firmware")

    def test_export_firmware_download(self):
        url = reverse("manager:device_export_firmware", args=[self.device.pk])
        resp = self.client.post(url, {"broadcast_duration_sec": 3, "sleep_duration_min": 2})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "text/x-c")
        body = resp.content.decode()
        self.assertIn("public_key[28]", body)
        self.assertIn("#define BEACON_WINDOW_S   3", body)
        self.assertIn("Content-Disposition", resp.headers)

    def test_export_arduino_page(self):
        url = reverse("manager:device_export_arduino", args=[self.device.pk])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "tag.ino")
        self.assertContains(resp, "Export Arduino sketch")

    def test_export_arduino_download(self):
        url = reverse("manager:device_export_arduino", args=[self.device.pk])
        resp = self.client.post(url, {"broadcast_duration_sec": 3, "sleep_duration_min": 2})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "text/x-c")
        body = resp.content.decode()
        self.assertIn("public_key[28]", body)
        self.assertIn("btStart()", body)
        self.assertIn("#define BEACON_WINDOW_S   3", body)
        self.assertIn("Content-Disposition", resp.headers)

    def test_macless_keyfile(self):
        resp = self.client.get(reverse("manager:macless_keyfile"))
        self.assertEqual(resp.status_code, 200)
        content = resp.content.decode()
        self.assertIn("Private key: ", content)
        self.assertIn("Hashed adv key: ", content)

    def test_device_create_generates_keypair(self):
        url = reverse("manager:device_create")
        resp = self.client.post(url, {
            "account": self.account.pk,
            "name": "new-tag",
            "description": "",
            "key_source": "generate",
            "active": "on",
            "broadcast_duration_sec": 10,
            "sleep_duration_min": 5,
        })
        self.assertEqual(resp.status_code, 302)
        device = Device.objects.get(name="new-tag")
        self.assertEqual(len(device.advertisement_key), 28)
        self.assertEqual(keygen.derive_public_x(device.private_key), device.advertisement_key)

    def test_device_create_page_renders_key_source_radios(self):
        resp = self.client.get(reverse("manager:device_create"))
        self.assertEqual(resp.status_code, 200)
        content = resp.content.decode()
        self.assertIn('type="radio"', content)
        self.assertIn('name="key_source"', content)
        self.assertIn('value="generate"', content)
        self.assertIn('value="import"', content)

    def test_device_create_without_key_source_rejected(self):
        url = reverse("manager:device_create")
        resp = self.client.post(url, {
            "account": self.account.pk,
            "name": "no-keysource",
            "active": "on",
            "broadcast_duration_sec": 10,
            "sleep_duration_min": 5,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "key_source")
        self.assertFalse(Device.objects.filter(name="no-keysource").exists())

    def test_device_create_preselects_account_when_single(self):
        resp = self.client.get(reverse("manager:device_create"))
        content = resp.content.decode()
        self.assertIn('name="account"', content)
        self.assertNotIn('<option value="" selected>---------</option>', content)

    def test_device_create_import_invalid_pair_rejected(self):
        url = reverse("manager:device_create")
        other_private, _ = keygen.generate_keypair()
        _, public = keygen.generate_keypair()
        resp = self.client.post(url, {
            "account": self.account.pk,
            "name": "bad-pair",
            "key_source": "import",
            "advertisement_key_hex": public.hex(),
            "private_key_hex": other_private.hex(),
            "broadcast_duration_sec": 10,
            "sleep_duration_min": 5,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Device.objects.filter(name="bad-pair").exists())

    def test_config_ini_download(self):
        url = reverse("manager:account_config_ini", args=[self.account.pk])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        content = resp.content.decode()
        self.assertIn("appleid = h@example.com", content)
        self.assertIn("appleid_pass = hunter2", content)

    def test_cannot_see_other_users_accounts_or_devices(self):
        other = _owner("intruder")
        foreign_account, foreign_device = _account_with_device(other)
        foreign_account.name = "Intruder home"
        foreign_account.email = "intruder-apple@example.com"
        foreign_account.save()
        foreign_device.name = "intruder-car"
        foreign_device.save()
        self.assertNotContains(
            self.client.get(reverse("manager:account_list")), foreign_account.name)
        self.assertNotContains(
            self.client.get(reverse("manager:device_list")), foreign_device.name)
        self.assertEqual(
            self.client.get(reverse("manager:account_detail", args=[foreign_account.pk])).status_code,
            404)
        self.assertEqual(
            self.client.get(reverse("manager:device_detail", args=[foreign_device.pk])).status_code,
            404)
        self.assertEqual(
            self.client.get(reverse("manager:device_history", args=[foreign_device.pk])).status_code,
            404)
        self.assertEqual(
            self.client.get(reverse("manager:device_history_data", args=[foreign_device.pk])).status_code,
            404)
        self.assertEqual(
            self.client.get(reverse("manager:device_export_arduino", args=[foreign_device.pk])).status_code,
            404)
        self.assertEqual(
            self.client.get(reverse("manager:account_config_ini", args=[foreign_account.pk])).status_code,
            404)


class PayloadLengthReferenceTest(SimpleTestCase):
    """Sanity-check the Find My advertisement layout used in the generated code."""

    def test_format_key_bytes(self):
        import re
        key = bytes(range(28))
        formatted = micropython._format_key_bytes(key)
        values = [int(m, 16) for m in re.findall(r"0x([0-9a-f]{2})", formatted)]
        self.assertEqual(bytes(values), key)


def _account_with_device(user=None):
    account = AppleAccount.objects.create(
        user=user or _owner(), name="Home", email="home@example.com", active=True)
    account.set_password("hunter2")
    account.save()
    private, public = keygen.generate_keypair()
    device = Device.objects.create(
        account=account, name="car",
        private_key_hex=private.hex(), advertisement_key_hex=public.hex())
    return account, device


class DeviceLocationModelTests(TestCase):
    def test_battery_levels_from_status(self):
        account, device = _account_with_device()
        roles = {0: "Full", 0x40: "Medium", 0x80: "Low", 0xC0: "Very Low"}
        for status, expected in roles.items():
            loc = DeviceLocation.objects.create(
                device=device, timestamp=timezone.now(), latitude=1.0, longitude=2.0,
                status=status)
            self.assertEqual(loc.battery_level, expected)

    def test_unique_per_device_timestamp(self):
        from django.db.utils import IntegrityError
        account, device = _account_with_device()
        ts = timezone.now()
        DeviceLocation.objects.create(device=device, timestamp=ts, latitude=1.0, longitude=2.0)
        with self.assertRaises(IntegrityError):
            DeviceLocation.objects.create(device=device, timestamp=ts, latitude=3.0, longitude=4.0)


class FetchLocationsTaskTests(TestCase):
    def _patch_findmy(self, login_result=None):
        mock_cls = patch("findmy.AppleAccount").start()
        self.addCleanup(patch.stopall)
        from findmy import LoginState
        mock_cls.from_json.side_effect = FileNotFoundError   # no cached session
        mock_cls.return_value.login.return_value = login_result or LoginState.LOGGED_IN
        acc = patch("findmy.FixedRollingKeyPairAccessory").start()
        self.accessory = acc.return_value  # shared object for dict lookup
        return mock_cls.return_value

    def _report(self, lat, lon, ts=None):
        from types import SimpleNamespace
        return SimpleNamespace(
            timestamp=ts or timezone.now(), latitude=lat, longitude=lon,
            horizontal_accuracy=25.0, status=0, confidence=1)

    def test_fetch_stores_reports_and_marks_ok(self):
        account, device = _account_with_device()
        fm = self._patch_findmy()
        fm.fetch_location_history.return_value = {
            self.accessory: [self._report(41.0, 2.0), self._report(41.1, 2.1)]}

        result = tasks.fetch_locations(account.pk, days=7)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["created"], 2)
        self.assertEqual(DeviceLocation.objects.filter(device=device).count(), 2)
        account.refresh_from_db()
        self.assertEqual(account.last_fetch_status, "ok")
        fm.to_json.assert_called_once()

    def test_fetch_needs_2fa_when_required(self):
        from findmy import LoginState
        account, device = _account_with_device()
        fm = self._patch_findmy(login_result=LoginState.REQUIRE_2FA)

        result = tasks.fetch_locations(account.pk)

        self.assertEqual(result["status"], "needs_2fa")
        account.refresh_from_db()
        self.assertEqual(account.last_fetch_status, "needs_2fa")
        self.assertEqual(DeviceLocation.objects.count(), 0)
        fm.fetch_location_history.assert_not_called()

    def test_fetch_reports_error_and_records_it(self):
        account, _ = _account_with_device()
        fm = self._patch_findmy()
        fm.fetch_location_history.side_effect = RuntimeError("Apple is down")

        result = tasks.fetch_locations(account.pk)

        self.assertEqual(result["status"], "error")
        account.refresh_from_db()
        self.assertEqual(account.last_fetch_status, "error")
        self.assertIn("RuntimeError", account.last_fetch_message)

    def test_fetch_marks_throttled_on_apple_503(self):
        from findmy import UnhandledProtocolError
        account, _ = _account_with_device()
        fm = self._patch_findmy()
        fm.fetch_location_history.side_effect = \
            UnhandledProtocolError("Error response for GSA request: 503")

        result = tasks.fetch_locations(account.pk)

        self.assertEqual(result["status"], "throttled")
        account.refresh_from_db()
        self.assertEqual(account.last_fetch_status, "throttled")
        self.assertIn("throttling", account.last_fetch_message)

    def test_fetch_reuses_cached_session(self):
        account, device = _account_with_device()
        mock_cls = patch("findmy.AppleAccount").start()
        self.addCleanup(patch.stopall)
        from findmy import LoginState
        restored = mock_cls.from_json.return_value
        restored.login_state = LoginState.LOGGED_IN
        acc = patch("findmy.FixedRollingKeyPairAccessory").start()
        restored.fetch_location_history.return_value = {
            acc.return_value: [self._report(1.0, 2.0)]}

        result = tasks.fetch_locations(account.pk)

        self.assertEqual(result["status"], "ok")
        restored.login.assert_not_called()

    def test_fetch_all_locations(self):
        account, _ = _account_with_device()
        with patch.object(tasks, "fetch_locations", return_value={"status": "ok"}) as mock_fetch:
            results = tasks.fetch_all_locations()
        self.assertIn(account.pk, results)
        mock_fetch.assert_called_once_with(account.pk, days=7)


class SafeCloseTaskTests(SimpleTestCase):
    def test_close_awaited_no_warning(self):
        import warnings

        class Fake:
            async def close(self):
                return None

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            tasks._safe_close(Fake())
        self.assertFalse([w for w in caught if w.category is RuntimeWarning])

    def test_close_failure_silent(self):
        import asyncio
        import warnings

        class Fake:
            def __init__(self):
                self._evt_loop = asyncio.new_event_loop()

            async def close(self):
                raise RuntimeError("boom")

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            tasks._safe_close(Fake())
        self.assertFalse([w for w in caught if w.category is RuntimeWarning])


class MapAndFetchViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="viewer", email="viewer@example.com", password="secret123")
        self.client.force_login(self.user)
        self.account, self.device = _account_with_device(self.user)

    def test_map_empty(self):
        resp = self.client.get(reverse("manager:map"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "No location data yet")
        self.assertContains(resp, "alert-info")
        self.assertContains(resp, "alert-dismissible")
        self.assertContains(resp, 'data-bs-dismiss="alert"')
        # OSM tile server 403s tile requests without a Referer header.
        self.assertContains(resp, '<meta name="referrer" content="origin">')

    def test_map_shows_latest_marker(self):
        from datetime import timedelta
        now = timezone.now()
        DeviceLocation.objects.create(
            device=self.device, timestamp=now, latitude=40.1, longitude=-3.0)
        DeviceLocation.objects.create(
            device=self.device, timestamp=now - timedelta(hours=1),
            latitude=40.2, longitude=-3.1)
        resp = self.client.get(reverse("manager:map"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.device.name)
        self.assertContains(resp, "40.1")
        self.assertNotContains(resp, "40.2")

    def test_fetch_all_queues_for_accounts_with_password(self):
        url = reverse("manager:fetch_all_locations")
        with patch("manager.views._enqueue_fetch", return_value=1) as enqueue:
            resp = self.client.post(url)
        self.assertEqual(resp.status_code, 302)
        enqueue.assert_called_once_with(self.account)

    def test_fetch_account_without_password_rejected(self):
        empty = AppleAccount.objects.create(
            user=self.user, name="Empty", email="empty@example.com", active=True)
        url = reverse("manager:account_fetch_locations", args=[empty.pk])
        with patch("manager.views._enqueue_fetch") as enqueue:
            resp = self.client.post(url)
        self.assertEqual(resp.status_code, 302)
        enqueue.assert_not_called()
        follow = self.client.get(resp.url)
        self.assertContains(follow, "Store the Apple ID password first", status_code=200)
        self.assertContains(follow, "alert-danger")
        self.assertContains(follow, "alert-dismissible")
        self.assertContains(follow, 'data-bs-dismiss="alert"')
        self.assertContains(follow, "bi-exclamation-triangle-fill")

    def test_fetch_account_queue(self):
        url = reverse("manager:account_fetch_locations", args=[self.account.pk])
        with patch("manager.views._enqueue_fetch", return_value=42) as enqueue:
            resp = self.client.post(url)
        self.assertEqual(resp.status_code, 302)
        enqueue.assert_called_once_with(self.account)


class FindMyLoginViewTests(TestCase):
    def setUp(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        self.user = get_user_model().objects.create_user(
            username="viewer", email="viewer@example.com", password="secret123")
        self.client.force_login(self.user)
        self.account, _ = _account_with_device(self.user)
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        settings_patch = self.settings(FINDMY_STATE_DIR=Path(self.tmp.name))
        settings_patch.enable()
        self.addCleanup(settings_patch.disable)

    def test_account_detail_shows_login_button(self):
        resp = self.client.get(reverse("manager:account_detail", args=[self.account.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, reverse("manager:account_findmy_login", args=[self.account.pk]))
        self.assertContains(resp, "Sign in to Apple")
        self.assertContains(resp, "not signed in")

    def test_login_hidden_without_password(self):
        empty = AppleAccount.objects.create(
            user=self.user, name="Empty", email="empty@example.com")
        resp = self.client.get(reverse("manager:account_detail", args=[empty.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "Sign in to Apple")

    def test_start_login_queues_task(self):
        url = reverse("manager:account_findmy_login", args=[self.account.pk])
        with patch("manager.views._enqueue_login", return_value=99) as enqueue:
            resp = self.client.post(url, {"action": "start"}, follow=True)
        enqueue.assert_called_once_with(self.account)
        self.assertRedirects(resp, self.account.get_absolute_url())
        self.assertContains(resp, "Apple sign-in queued")
        self.account.refresh_from_db()
        self.assertEqual(self.account.last_fetch_status, "logging_in")

    def test_2fa_page_reads_pending_meta(self):
        from manager import findmy_auth
        findmy_auth.save_pending_meta(self.account, {
            "methods": [{"index": 0, "kind": "sms", "label": "SMS (+1 •••• 1234)"}],
            "requested": None,
        })
        findmy_auth.pending_path(self.account).write_text("{}", encoding="utf-8")
        page = self.client.get(reverse("manager:account_findmy_login", args=[self.account.pk]))
        self.assertContains(page, "Two-factor authentication")
        self.assertContains(page, "SMS (+1 •••• 1234)")

    def test_submit_2fa_success(self):
        from manager import findmy_auth
        findmy_auth.save_pending_meta(self.account, {
            "methods": [{"index": 0, "kind": "sms", "label": "SMS"}],
            "requested": {"index": 0, "kind": "sms", "label": "SMS"},
        })
        url = reverse("manager:account_findmy_login", args=[self.account.pk])
        with patch("manager.views.findmy_auth.submit_2fa",
                   return_value={"status": "logged_in"}) as submit:
            resp = self.client.post(url, {"action": "submit", "method": "0", "code": "123456"})
        submit.assert_called_once_with(self.account, "0", "123456")
        self.assertRedirects(resp, self.account.get_absolute_url())

    def test_login_scoped_to_owner(self):
        other = get_user_model().objects.create_user(
            username="other", email="other@example.com", password="secret123")
        foreign, _ = _account_with_device(other)
        url = reverse("manager:account_findmy_login", args=[foreign.pk])
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.post(url, {"action": "start"}).status_code, 404)


class FindMyAuthTests(TestCase):
    def setUp(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        self.account, _ = _account_with_device()
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        settings_patch = self.settings(FINDMY_STATE_DIR=Path(self.tmp.name))
        settings_patch.enable()
        self.addCleanup(settings_patch.disable)

    def test_start_login_caches_session(self):
        from findmy import LoginState
        from manager import findmy_auth
        fm = patch("findmy.AppleAccount").start()
        self.addCleanup(patch.stopall)
        instance = fm.return_value
        instance.login.return_value = LoginState.LOGGED_IN
        result = findmy_auth.start_login(self.account)
        self.assertEqual(result["status"], "logged_in")
        instance.to_json.assert_called_once()
        instance.login.assert_called_once_with(self.account.email, "hunter2")

    def test_start_login_needs_2fa(self):
        from findmy import LoginState
        from manager import findmy_auth
        from types import SimpleNamespace
        fm = patch("findmy.AppleAccount").start()
        self.addCleanup(patch.stopall)
        instance = fm.return_value
        instance.login.return_value = LoginState.REQUIRE_2FA
        instance.get_2fa_methods.return_value = [
            SimpleNamespace(phone_number="+1 •••• 99"),
            SimpleNamespace(),
        ]
        result = findmy_auth.start_login(self.account)
        self.assertEqual(result["status"], "needs_2fa")
        self.assertEqual(result["methods"][0]["kind"], "sms")
        self.assertEqual(result["methods"][1]["kind"], "trusted_device")
        instance.to_json.assert_called_once()
        self.assertTrue(findmy_auth.pending_meta_path(self.account).is_file())

    def test_login_task_records_session(self):
        from manager import findmy_auth
        with patch.object(findmy_auth, "start_login", return_value={"status": "logged_in"}):
            result = tasks.login_findmy(self.account.pk)
        self.assertEqual(result["status"], "logged_in")
        self.account.refresh_from_db()
        self.assertEqual(self.account.last_fetch_status, "ok")
        self.assertIn("session cached", self.account.last_fetch_message.lower())