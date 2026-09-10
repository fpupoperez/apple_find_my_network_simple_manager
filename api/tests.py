"""Tests for the DRF API (v1) and django-allauth headless authentication."""

import uuid

from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from manager import keygen
from manager.models import AppleAccount, Device, DeviceLocation

User = get_user_model()

AUTH_BASE = "/api/app/v1/auth/"


def _keypair():
    private, public = keygen.generate_keypair()
    return private.hex(), public.hex()


class ApiTestCaseBase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("tester", "test@example.com", "secret123")
        EmailAddress.objects.create(
            user=self.user, email=self.user.email, primary=True, verified=True)
        self.priv, self.pub = _keypair()

        login = self.client.post(
            AUTH_BASE + "login",
            data={"username": "tester", "password": "secret123"},
            content_type="application/json",
        )
        self.assertEqual(login.status_code, 200, login.content)
        meta = login.json()["meta"]
        self.access_token = meta["access_token"]
        self.session_token = meta["session_token"]
        self.default_headers = {"HTTP_AUTHORIZATION": "Bearer " + self.access_token}

    def _post(self, url, payload=None, headers=None):
        return self.client.post(
            url, data=payload or {},
            content_type="application/json",
            **self._auth(headers),
        )

    def _get(self, url, headers=None):
        return self.client.get(url, **self._auth(headers))

    def _put(self, url, payload, headers=None):
        return self.client.put(
            url, data=payload, content_type="application/json",
            **self._auth(headers),
        )

    def _delete(self, url, headers=None):
        return self.client.delete(url, **self._auth(headers))

    def _auth(self, headers=None):
        if headers is None:
            return self.default_headers
        return headers


class AuthTests(ApiTestCaseBase):
    def _login(self, payload, headers=None):
        return self.client.post(
            AUTH_BASE + "login", data=payload,
            content_type="application/json",
            **(headers or {}),
        )

    def test_login_roundtrip(self):
        response = self._login({
            "username": "tester", "password": "secret123",
        })
        self.assertEqual(response.status_code, 200)
        json = response.json()
        self.assertEqual(json["status"], 200)
        self.assertEqual(json["data"]["user"]["username"], "tester")
        self.assertTrue(json["meta"]["is_authenticated"])
        self.assertTrue(json["meta"]["access_token"])
        self.assertTrue(json["meta"]["session_token"])
        self.assertEqual(json["meta"]["token_type"], "Bearer")

    def test_login_with_email(self):
        response = self._login({
            "email": "test@example.com", "password": "secret123",
        })
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["data"]["user"]["username"], "tester")

    def test_login_rejects_wrong_password(self):
        response = self._login({"username": "tester", "password": "wrong"})
        self.assertIn(response.status_code, (400, 401))

    def test_drf_endpoints_require_auth(self):
        url = reverse("api:account-list")
        self.assertEqual(self.client.get(url).status_code, 403)

    def test_access_token_works_on_drf_endpoints(self):
        # The access token returned by allauth authenticates DRF resources.
        response = self.client.get(
            reverse("api:account-list"),
            HTTP_AUTHORIZATION="Bearer " + self.access_token,
        )
        self.assertEqual(response.status_code, 200, response.content)

    def test_session_endpoint_reports_user(self):
        response = self.client.get(
            AUTH_BASE + "session", HTTP_X_SESSION_TOKEN=self.session_token)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()["meta"]["is_authenticated"])
        self.assertEqual(response.json()["data"]["user"]["username"], "tester")

    def test_logout_revokes_access_token(self):
        logout = self.client.delete(
            AUTH_BASE + "session",
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=self.session_token,
        )
        body = logout.json()
        self.assertFalse(body["meta"]["is_authenticated"])
        stale = self.client.get(
            reverse("api:account-list"),
            HTTP_AUTHORIZATION="Bearer " + self.access_token,
        )
        self.assertIn(stale.status_code, (401, 403))
        from rest_framework.authtoken.models import Token
        self.assertEqual(Token.objects.filter(user=self.user).count(), 0)

    def test_browsable_api_login_and_logout(self):
        from django.test import Client

        html = {"HTTP_ACCEPT": "text/html"}
        guest = Client()
        denied = guest.get("/api/v1/", **html)
        self.assertContains(denied, "Log in", status_code=403)
        self.assertContains(denied, reverse("rest_framework:login"), status_code=403)

        login_page = guest.get(reverse("rest_framework:login") + "?next=/api/v1/")
        self.assertEqual(login_page.status_code, 200)
        self.assertContains(login_page, "Find My manager API")

        posted = guest.post(reverse("rest_framework:login"), {
            "username": "tester", "password": "secret123", "next": "/api/v1/",
        })
        self.assertEqual(posted.status_code, 302)
        self.assertEqual(posted.url, "/api/v1/")

        authed = guest.get("/api/v1/", **html)
        self.assertEqual(authed.status_code, 200)
        self.assertContains(authed, "Log out")
        self.assertContains(authed, reverse("rest_framework:logout"))

        logged_out = guest.post(reverse("rest_framework:logout"))
        self.assertRedirects(logged_out, "/api/v1/", fetch_redirect_response=False)
        after = guest.get("/api/v1/", **html)
        self.assertContains(after, "Log in", status_code=403)
    def test_create_list_update_retrieve_delete(self):
        create = self._post(reverse("api:account-list"), {
            "name": "Home", "email": "home@example.com",
            "password": "apple-secret", "active": True,
        })
        self.assertEqual(create.status_code, 201, create.content)
        body = create.json()
        self.assertNotIn("password", body)
        pk = body["id"]
        uuid.UUID(pk)
        self.assertEqual(body["device_count"], 0)
        self.assertEqual(body["last_fetch_status"], "")

        detail = self._get(reverse("api:account-detail", args=[pk]))
        self.assertEqual(detail.status_code, 200)
        self.assertNotIn("password", detail.json())

        update = self._put(reverse("api:account-detail", args=[pk]), {
            "name": "Work", "email": "home@example.com", "active": False,
        })
        self.assertEqual(update.status_code, 200, update.content)
        self.assertEqual(update.json()["name"], "Work")

        account = AppleAccount.objects.get(pk=pk)
        self.assertEqual(account.get_password(), "apple-secret")

        delete = self._delete(reverse("api:account-detail", args=[pk]))
        self.assertEqual(delete.status_code, 204)

    def test_account_config_ini(self):
        account = AppleAccount.objects.create(
            user=self.user, name="Home", email="home@example.com")
        account.set_password("secret")
        account.save()
        response = self._get(reverse("api:account-config-ini", args=[account.pk]))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("appleid = home@example.com", response.json()["content"])
        self.assertIn("appleid_pass = secret", response.json()["content"])

    def test_fetch_requires_password(self):
        account = AppleAccount.objects.create(
            user=self.user, name="NoPass", email="nopass@example.com")
        response = self._post(reverse("api:account-fetch", args=[account.pk]))
        self.assertEqual(response.status_code, 400)


class DeviceApiTests(ApiTestCaseBase):
    def setUp(self):
        super().setUp()
        self.account = AppleAccount.objects.create(
            user=self.user, name="Home", email="home@example.com")

    def test_create_generates_keypair(self):
        response = self._post(reverse("api:device-list"), {
            "account": self.account.pk,
            "name": "Keys", "active": True,
            "broadcast_duration_sec": 12, "sleep_duration_min": 7,
        })
        self.assertEqual(response.status_code, 201, response.content)
        device = Device.objects.get(pk=response.json()["id"])
        self.assertTrue(device.private_key_hex and device.advertisement_key_hex)
        self.assertTrue(response.json()["has_keypair"])

    def test_create_import_keypair(self):
        response = self._post(reverse("api:device-list"), {
            "account": self.account.pk, "name": "Imported",
            "private_key_hex": self.priv, "advertisement_key_hex": self.pub,
        })
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertNotIn("advertisement_key_hex", body)

    def test_import_rejects_mismatched_pair(self):
        other_priv, _ = _keypair()
        response = self._post(reverse("api:device-list"), {
            "account": self.account.pk, "name": "Bad",
            "private_key_hex": other_priv, "advertisement_key_hex": self.pub,
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("keypair", response.json())

    def test_keys_endpoint(self):
        device = Device(
            account=self.account, name="Keys",
            private_key_hex=self.priv, advertisement_key_hex=self.pub,
        )
        device.save()
        response = self._get(reverse("api:device-keys", args=[device.pk]))
        self.assertEqual(response.status_code, 200, response.content)
        json = response.json()
        self.assertEqual(json["private_key_hex"], self.priv)
        self.assertEqual(json["advertisement_key_hex"], self.pub)
        self.assertEqual(json["hashed_key_b64"], device.hashed_key_b64)

    def test_exports(self):
        device = Device(
            account=self.account, name="tag 1",
            private_key_hex=self.priv, advertisement_key_hex=self.pub,
        )
        device.save()
        for name, path, needle in [
            ("micropython", "api:device-export-micropython", "Find My offline beacon"),
            ("firmware", "api:device-export-firmware", "#include"),
            ("arduino", "api:device-export-arduino", "void setup"),
        ]:
            response = self._get(reverse(path, args=[device.pk]))
            self.assertEqual(response.status_code, 200,
                             "{} -> {}".format(name, response.content[:200]))
            json = response.json()
            self.assertEqual(json["fmt"], name)
            self.assertTrue(json["filename"].endswith(
                {"micropython": ".py", "firmware": ".c", "arduino": ".ino"}[name]))
            self.assertIn(needle, json["content"])
            self.assertEqual(json["device"], str(device.pk))

    def test_keyfile_batch(self):
        device = Device(
            account=self.account, name="tag 1",
            private_key_hex=self.priv, advertisement_key_hex=self.pub,
        )
        device.save()
        response = self._get(reverse("api:keyfile"))
        self.assertEqual(response.status_code, 200, response.content)
        content = response.json()["content"]
        self.assertIn("Hashed adv key:", content)


class LocationApiTests(ApiTestCaseBase):
    def setUp(self):
        super().setUp()
        self.account = AppleAccount.objects.create(
            user=self.user, name="Home", email="home@example.com")
        self.device = Device(
            account=self.account, name="tag",
            private_key_hex=self.priv, advertisement_key_hex=self.pub,
        )
        self.device.save()

    def _loc(self, ts, lat, lon, **kw):
        return DeviceLocation.objects.create(
            device=self.device, timestamp=ts, latitude=lat, longitude=lon, **kw)

    def test_list_filter_map(self):
        import datetime
        base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        older = self._loc(base, 1.0, 2.0)
        newer = self._loc(base + datetime.timedelta(minutes=5), 3.0, 4.0,
                          horizontal_accuracy=5.0, status=0)

        url = reverse("api:location-list")
        response = self._get(url)
        self.assertEqual(response.status_code, 200, response.content)
        results = response.json()["results"]
        fixed = DeviceLocation.objects.filter(pk__in=[older.pk, newer.pk]).order_by("pk")
        self.assertEqual(len(results), fixed.count())

        filtered = self._get(url + "?device={}".format(self.device.pk))
        self.assertTrue(filtered.json()["count"] >= 1)

        map_response = self._get(reverse("api:map"))
        markers = map_response.json()
        latest = max(markers, key=lambda m: m["timestamp"])
        self.assertEqual(latest["latitude"], 3.0)
        self.assertEqual(latest["device_name"], "tag")


class OwnershipIsolationTests(ApiTestCaseBase):
    def setUp(self):
        super().setUp()
        self.other = User.objects.create_user("other", "other@example.com", "secret123")
        self.foreign_account = AppleAccount.objects.create(
            user=self.other, name="Secret", email="secret@example.com")
        priv, pub = _keypair()
        self.foreign_device = Device.objects.create(
            account=self.foreign_account, name="hidden-tag",
            private_key_hex=priv, advertisement_key_hex=pub)

    def test_list_excludes_foreign_accounts_and_devices(self):
        accounts = self._get(reverse("api:account-list")).json()["results"]
        devices = self._get(reverse("api:device-list")).json()["results"]
        self.assertNotIn(str(self.foreign_account.pk), [row["id"] for row in accounts])
        self.assertNotIn(str(self.foreign_device.pk), [row["id"] for row in devices])

    def test_detail_and_exports_are_hidden(self):
        self.assertEqual(
            self._get(reverse("api:account-detail", args=[self.foreign_account.pk])).status_code, 404)
        self.assertEqual(
            self._get(reverse("api:device-detail", args=[self.foreign_device.pk])).status_code, 404)
        self.assertEqual(
            self._get(reverse("api:device-keys", args=[self.foreign_device.pk])).status_code, 404)
        self.assertEqual(
            self._get(reverse("api:account-config-ini", args=[self.foreign_account.pk])).status_code, 404)

    def test_cannot_attach_device_to_foreign_account(self):
        response = self._post(reverse("api:device-list"), {
            "account": self.foreign_account.pk, "name": "stolen",
        })
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Device.objects.filter(name="stolen").exists())

    def test_created_account_belongs_to_caller(self):
        response = self._post(reverse("api:account-list"), {
            "name": "Mine", "email": "mine@example.com",
        })
        self.assertEqual(response.status_code, 201, response.content)
        account = AppleAccount.objects.get(pk=response.json()["id"])
        self.assertEqual(account.user_id, self.user.pk)