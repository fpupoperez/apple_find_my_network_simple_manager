# Find My manager

A Django service for managing ESP32 Find My locator tags (“AirTag clones”)
and the Apple accounts used to decrypt their reports.

It covers the full loop:

- register users and sign in (email verification, password reset, MFA);
- store **Apple IDs** used by a companion
  [macless-haystack](https://github.com/dchristl/macless-haystack) container
  (password encrypted at rest, exported as `config.ini`);
- store each **device keypair** (NIST P-224, same as macless-haystack
  `generate_keys.py`): the 28-byte *advertisement key* the tag broadcasts and
  the *private key* used to decrypt location reports;
- **export firmware** for the tag — MicroPython `main.py`, native **ESP-IDF**
  `main.c`, or **Arduino** `tag.ino`;
- **export the macless-haystack `.keys` file** so the container can decrypt
  reports;
- **log in to Apple** (including 2FA) and **fetch location history** via
  [FindMy.py](https://github.com/malmeloo/FindMy.py) in background
  [django-q2](https://django-q2.readthedocs.io/) tasks;
- show the latest positions on a **map** (MapLibre + OSM tiles).

Apple IDs, devices, and locations belong to the signed-in Django user. Two
users can store the same Apple email independently.

> Development defaults (`ALLOWED_HOSTS = ["*"]`, console email, insecure
> `SECRET_KEY`) are for a **trusted network only**. The database holds Apple
> credentials and private keys.

---

## Architecture

```
Browser UI  (/login, /accounts, /devices, /map, /profile)
     │
     │  session cookie
     ▼
┌────────────────────────────────────────────────────────────┐
│  config/          Django project (settings, URLs, middleware)│
│  manager/         HTML UI, models, firmware export, tasks    │
│  api/             DRF resources under /api/v1/               │
│  allauth          Browser /account/* + headless /api/app/v1/ │
│  django-q2        Background Apple login + location fetch    │
└───────────────┬─────────────────────────────┬──────────────┘
                │                             │
                ▼                             ▼
         SQLite (db.sqlite3)          .findmy/ session JSON
         users, Apple accounts,        anisette libs + cached
         devices, locations            Apple login state
                │
                ▼
         FindMy.py  ──►  Apple Find My network
```

### Django apps

| App | Role |
| --- | --- |
| `config` | Settings, root URLs, login-required middleware |
| `manager` | Models, manager UI, firmware generators, Find My login/fetch |
| `api` | Authenticated JSON API (DRF) scoped to the current user |
| `allauth` | Signup, email verification, password reset, MFA, headless API |
| `django_q` | ORM-backed worker (`qcluster`) — no Redis required |

### Data model

All manager rows use **UUID primary keys**.

```
User  1──*  AppleAccount  1──*  Device  1──*  DeviceLocation
```

- **AppleAccount** — label, Apple ID email (unique per user), encrypted
  password, active flag, last fetch status/message, notes.
- **Device** — name, encrypted P-224 private + advertisement keys, beacon
  timing (`broadcast_duration_sec` / `sleep_duration_min`), active flag.
- **DeviceLocation** — timestamp, lat/lon, accuracy, status/battery, unique
  per `(device, timestamp)`.

QuerySets expose `.for_user(user)` so views and the API never leak another
user’s rows.

### Request surfaces

| Prefix | Who | Auth |
| --- | --- | --- |
| `/` | Manager UI | Django session (`LOGIN_URL=/login/`) |
| `/account/` | allauth browser pages | Public for signup/login/reset; session for manage |
| `/api/app/v1/` | allauth **headless** JSON | Session token during the auth flow |
| `/api/v1/` | DRF resources | Session **or** `Authorization: Bearer <token>` |
| `/api/auth/` | Browsable API login/logout | Django session |
| `/admin/` | Django admin | Staff login |
| `/static/` | CSS, Bootstrap, map assets | Public |

`ManagerLoginRequiredMiddleware` requires a session for everything except
`/account/`, `/api/`, `/admin/`, `/static/`, and `/favicon.ico`. `/login/`
is reachable as `LOGIN_URL`. The API enforces its own authentication.

---

## Quick start

Django reads `config/settings.py`. The copy in git is the template
`config/settings.dist.py`. **On every deploy (and on a fresh checkout),
copy it before you run migrations or the server:**

```bash
cp config/settings.dist.py config/settings.py
```

Then set a real `SECRET_KEY`, tighten `DEBUG` / `ALLOWED_HOSTS`, and switch
`EMAIL_BACKEND` if this is not a local workshop. Do not commit the local
`settings.py` if it contains secrets.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

In a **second terminal**, start the worker (Apple login and location fetches):

```bash
source .venv/bin/activate
python manage.py qcluster
```

Open http://127.0.0.1:8000/

1. **Create account** (or `/account/signup/`) — unique email + username + password.
2. Confirm the address. In development the verification email is printed to
   the **console** (`EMAIL_BACKEND` is the console backend).
3. Sign in with **username or email** at `/login/`.
4. Add an Apple account, create a device, export firmware, sign in to Apple,
   then fetch locations.

`createsuperuser` still works for `/admin/`. Admin-created users without an
allauth `EmailAddress` can sign in on `/login/` with username; allauth
signups must verify email first.

---

## User accounts (allauth)

### Browser

- **Register** — email is required and must be unique. A verification message
  is sent; the confirmation link can be opened with GET
  (`ACCOUNT_CONFIRM_EMAIL_ON_GET`). After confirm, the user is signed in
  (`ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION`).
- **Sign in** (`/login/`) — username **or** email, plus password. Links for
  **sign up**, **forgot password**, and (if you enable them) sign-in code /
  passkey, same as allauth’s own login page.
- **Profile** (`/profile/`) — user details and links to allauth operations:
  emails, password, MFA (TOTP + recovery codes), reauthenticate, sign out.
- **Password reset** — `/account/password/reset/`.
- **MFA** — `/account/2fa/` (authenticator app + recovery codes).

Navbar: operations (Dashboard, Apple accounts, Devices, Map, New device) are
hidden until signed in. The username is a dropdown with Profile and Sign out.

### Headless / mobile (`/api/app/v1/`)

The allauth **app** client exposes JSON login, signup, logout, email verify,
password reset, and MFA. After a successful flow, `api.auth.DrfTokenStrategy`
issues a DRF token:

```json
{
  "meta": {
    "is_authenticated": true,
    "access_token": "<drf-token>",
    "token_type": "Bearer",
    "session_token": "<django-session-key>"
  }
}
```

Send `Authorization: Bearer <access_token>` to `/api/v1/...`.
`HEADLESS_SERVE_SPECIFICATION = True` publishes the OpenAPI-style spec next
to the headless routes.

---

## Manager workflow

1. **Apple account** — `Apple accounts → New account`. Store the Apple ID
   email and password the macless-haystack container (and FindMy.py) will use.
2. **Sign in to Apple** on that account page. This queues
   `manager.tasks.login_findmy` (same logic as `manage.py login_findmy`):
   stored password, retries on Apple HTTP 5xx, session written to
   `.findmy/account_<uuid>.json`. If Apple asks for 2FA, complete SMS or
   trusted-device on the following page. Keep `qcluster` running.
3. **Create a device** — a fresh P-224 keypair is generated, or import an
   existing pair from macless-haystack `generate_keys.py`.
4. On the **device** page:
   - Export MicroPython / ESP-IDF / Arduino firmware (tune broadcast/sleep).
   - Copy *macless-haystack key lines* or download **`.keys`**. The private
     key stays here (and in the container), never on the tag.
5. On the **account** page: download **macless `config.ini`**
   (`appleid` / `appleid_pass`).
6. **Fetch locations** — account “Fetch locations now” or dashboard
   “Fetch all”. Jobs run in `qcluster`. The map shows the latest report per
   active device.

Account and device pages split **Edit / Map / Delete** from operational
buttons (Apple sign-in, fetch, exports).

### Apple session & 2FA

Background fetches reuse the cached session. First login (or after expiry)
needs 2FA once.

**UI (preferred):** account page → **Sign in to Apple** → complete 2FA if
asked.

**CLI:**

```bash
python manage.py login_findmy "Home"
```

(`Home` is the account name or Apple email.) Interactive Trusted Device / SMS
prompt; then the same session file is written.

- Session JSON is **plaintext** (includes Apple tokens). Keep `.findmy/` on
  the trusted host.
- Optional remote anisette: set `FINDMY_ANISETTE_URL` (e.g.
  `http://anisette:6969`). Empty = bundled local provider
  (`.findmy/ani_libs.bin`).
- Last fetch / login status (`ok`, `logging_in`, `needs_2fa`, `throttled`,
  `error`) is shown on the dashboard and account page.
- Apple 503s are treated as throttling — wait; repeated attempts extend the
  block.

Schedule periodic fetches:

```bash
python manage.py schedule_fetch --every 15 --unit minutes
```

---

## REST API (`/api/v1/`)

All endpoints require authentication and are scoped to `request.user`.

| Method | Path | Purpose |
| --- | --- | --- |
| CRUD | `/api/v1/accounts/` | Apple accounts |
| GET | `/api/v1/accounts/{id}/config.ini/` | macless `config.ini` payload |
| POST | `/api/v1/accounts/{id}/fetch/` | Queue fetch for one account |
| CRUD | `/api/v1/devices/` | Devices |
| GET | `/api/v1/devices/{id}/keys/` | Advertisement + private key hex |
| GET | `/api/v1/devices/{id}/export/micropython/` | `main.py` |
| GET | `/api/v1/devices/{id}/export/firmware/` | ESP-IDF `main.c` |
| GET | `/api/v1/devices/{id}/export/arduino/` | `tag.ino` |
| GET | `/api/v1/locations/` | Stored reports |
| GET | `/api/v1/map/` | Latest marker per active device |
| GET | `/api/v1/keys/` | Combined `.keys` file |
| POST | `/api/v1/fetch/` | Queue fetch for every account with a password |

The browsable API at `/api/v1/` uses session login at `/api/auth/login/`.

---

## Firmware exports

### MicroPython (`main.py`)

Battery-oriented loop: build Apple’s offline advertisement, broadcast briefly,
deep-sleep. **Cannot set the BLE random static address**, so Apple’s network
often will not match the tag. Useful for experiments; use native firmware for
real tracking.

```python
my_public_key = bytes([
    0x1f, 0xfa, ...   # 28-byte advertisement key
])
```

`cadence` in the generated script follows the device’s broadcast / sleep
fields. The payload matches the offline Find My format:
`020106 21 ff 4c00 1219 00 <key[:22]> <key[22:28]> 00`.

The 28-byte advertisement key is the P-224 public **x-coordinate** (macless
“Advertisement key”). SHA-256 of that key (“Hashed adv key”) is the
identifier when fetching reports.

### ESP-IDF (`main.c`)

Native Bluedroid firmware with the key baked in:

- BLE **random static address = key[0:6]** via `esp_ble_gap_set_rand_addr()`
- 31-byte OpenHaystack payload
  `1eff 4c00 1219 00 | key[6:28] | key[0]>>6 | 00`

Those two fragments reassemble the 28-byte key on Apple’s side — this is why
native firmware is required for a matchable tag.

```bash
python manage.py export_firmware car -o main.c --broadcast 10 --sleep 5
# device id (UUID) or name
idf.py set-target esp32s3 && idf.py build && idf.py -p PORT flash monitor
```

The firmware advertises for a beacon window, then rests with the radio on.
Long delays cut average current; coin-cell life still wants a deep-sleep
design.

### Arduino (`tag.ino`)

Same address + payload scheme for the **ESP32 Arduino core** (raw ESP-IDF BLE
API the core exposes):

```bash
python manage.py export_arduino car -o tag.ino --broadcast 10 --sleep 5
```

Open in the Arduino IDE, select the board, Upload. If `btStart() failed`
appears, check **Tools → Board**, the USB cable, and upload speed.

---

## Management commands

Device arguments accept a **UUID or unique name**. Account arguments accept
**name or Apple email**.

```bash
# N devices with fresh keypairs under an account
python manage.py generate_devices 4 --account "Home" --prefix tag

python manage.py export_micropython car -o main.py --broadcast 10 --sleep 5
python manage.py export_firmware car -o main.c --broadcast 10 --sleep 5
python manage.py export_arduino car -o tag.ino --broadcast 10 --sleep 5

# Interactive Apple login (2FA on the terminal; same session file as the UI)
python manage.py login_findmy "Home"

# One-off / cron fetch (does not need qcluster)
python manage.py fetch_locations --all --days 7

python manage.py schedule_fetch --every 15 --unit minutes
```

---

## Settings

The committed template is `config/settings.dist.py`. Deployment (and any
machine that does not already have a local file) **must** copy it:

```bash
cp config/settings.dist.py config/settings.py
```

Django then loads `config/settings.py`. Edit that copy — never the `.dist`
file — for host-specific values:

| Setting | Meaning |
| --- | --- |
| `FINDMY_STATE_DIR` | Cached Apple sessions + anisette libs (default `.findmy/`) |
| `FINDMY_ANISETTE_URL` | Remote anisette; empty = local provider |
| `Q_CLUSTER` | django-q2 (ORM broker, 600s timeout for Apple calls) |
| `ACCOUNT_*` | Signup fields, unique email, mandatory verification, login methods |
| `EMAIL_BACKEND` | Console in development — switch to SMTP for real mail |
| `HEADLESS_*` | Headless allauth client + DRF token strategy |
| `SECRET_KEY` | Also derives Fernet keys for Apple passwords and device keys |
| `LOGIN_URL` / redirects | Manager session login at `/login/` |
| `SECURE_PROXY_SSL_HEADER` | Trust `X-Forwarded-Proto: https` from the TLS reverse proxy |
| `USE_X_FORWARDED_HOST` / `_PORT` | Use the public Host / port the proxy forwards |
| `CSRF_TRUSTED_ORIGINS` | Scheme + host Django accepts for CSRF (include `https://your.domain`) |
| `CORS_ALLOWED_ORIGINS` | Browser origins allowed to call `/api/` (defaults to the CSRF list) |
| `HTTPS` (env) | `1` to mark session/CSRF cookies `Secure` behind TLS |

Behind an SSL reverse proxy, forward `X-Forwarded-Proto: https` and set
(or export) the public origin on both CSRF and CORS lists:

```bash
export ALLOWED_HOSTS=findmy.example.com
export CSRF_TRUSTED_ORIGINS=https://findmy.example.com
export CORS_ALLOWED_ORIGINS=https://findmy.example.com
export HTTPS=1
```

---

## Tests

```bash
python manage.py test manager api
```

`manager` covers keys, exports, ownership, UI, Apple login task, and allauth
signup/login. `api` covers headless auth and DRF resources.

---

## Security

- Apple ID passwords and device private keys are encrypted at rest with
  Fernet (AES-GCM). The key is derived from Django’s `SECRET_KEY`. Change it
  before any real deployment; rotating it invalidates stored secrets.
- Device pages show keys in plaintext for copy/paste. This is a local
  management tool — do not expose it on the public internet without a reverse
  proxy, HTTPS, and a real email backend.
- Cached Apple sessions in `.findmy/` are reusable login state. Restrict
  filesystem permissions.
- Keys are not bound to a given Apple ID: reports are fetched with *an* Apple
  account and decrypted with *that tag’s* private key.
- Users only see their own accounts, devices, and locations.

---

## Project layout

```
config/                 Django project
  settings.dist.py      Committed settings template (copy on deploy)
  settings.py           Local copy Django actually loads (not the template)
  urls.py               /admin /api /account / (manager)
  middleware.py         Login-required except public prefixes
manager/                UI + domain logic
  models.py             AppleAccount, Device, DeviceLocation
  views.py              Pages, exports, enqueue login/fetch
  findmy_auth.py        Shared Apple login / 2FA / session cache
  tasks.py              django-q2: login_findmy, fetch_locations
  keygen.py / *export*  P-224 keys and firmware generators
  templates/manager/    Bootstrap 5 dark UI
api/                    DRF viewsets + Bearer token strategy
templates/              Admin, DRF, allauth element overrides
```
