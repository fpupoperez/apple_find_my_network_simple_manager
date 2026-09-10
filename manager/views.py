"""Views for the Find My manager."""

from uuid import UUID

from django.contrib import messages
from django.contrib.auth.views import LoginView
from django.db.models import ProtectedError, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django_datatables_view.base_datatable_view import BaseDatatableView

from manager import arduino, esp_idf, findmy_auth, micropython
from manager.forms import (
    AccountForm, DeviceForm, FirmwareExportForm, ManagerAuthenticationForm,
    MicropythonExportForm,
)
from manager.models import AppleAccount, Device, DeviceLocation


class ManagerLoginView(LoginView):
    """Session login with the same allauth entrance options as /account/login/."""

    template_name = "manager/login.html"
    redirect_authenticated_user = True
    authentication_form = ManagerAuthenticationForm

    def get_context_data(self, **kwargs):
        from allauth.account.internal.templatekit import get_entrance_context_data

        context = super().get_context_data(**kwargs)
        context.update(get_entrance_context_data(self.request))
        return context


def _accounts(request):
    return AppleAccount.objects.prefetch_related("devices").for_user(request.user)


def _devices(request):
    return Device.objects.select_related("account").for_user(request.user)


def _get_account(request, pk):
    return get_object_or_404(AppleAccount.objects.for_user(request.user), pk=pk)


def _get_device(request, pk):
    return get_object_or_404(
        Device.objects.select_related("account").for_user(request.user), pk=pk)


def _parse_uuid(value):
    try:
        return UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


def _attachment(source, filename, content_type="text/plain"):
    response = HttpResponse(source.encode("utf-8"), content_type=content_type)
    response["Content-Disposition"] = 'attachment; filename="{}"'.format(filename)
    return response


def profile(request):
    """Signed-in user profile plus links to allauth account operations."""
    accounts = _accounts(request)
    devices = _devices(request)
    return render(request, "manager/profile.html", {
        "profile_user": request.user,
        "total_accounts": accounts.count(),
        "total_devices": devices.count(),
        "active_devices": devices.filter(active=True).count(),
    })


def dashboard(request):
    accounts = _accounts(request)
    devices = _devices(request)
    return render(request, "manager/dashboard.html", {
        "accounts": accounts,
        "total_devices": devices.count(),
        "active_devices": devices.filter(active=True).count(),
        "total_accounts": accounts.count(),
    })


# --------------------------------------------------------------------------
# Apple accounts
# --------------------------------------------------------------------------

def account_list(request):
    # device_count is a model @property; prefetch the relation so it does not
    # re-query per row (annotate would clash with the read-only attribute).
    accounts = _accounts(request)
    return render(request, "manager/account_list.html", {"accounts": accounts})


def account_detail(request, pk):
    account = _get_account(request, pk)
    config_ini = account_config_ini(account) if account.password_is_set else None
    return render(request, "manager/account_detail.html", {
        "account": account,
        "devices": account.devices.all(),
        "config_ini": config_ini,
        "findmy_session_cached": findmy_auth.session_cached(account),
        "findmy_login_pending": findmy_auth.login_in_progress(account),
    })


def account_create(request):
    if request.method == "POST":
        form = AccountForm(request.POST, user=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Apple account created.")
            return redirect(form.instance.get_absolute_url())
    else:
        form = AccountForm(user=request.user)
    return render(request, "manager/account_form.html", {"form": form, "title": "New Apple account"})


def account_update(request, pk):
    account = _get_account(request, pk)
    if request.method == "POST":
        form = AccountForm(request.POST, instance=account, user=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Apple account updated.")
            return redirect(account.get_absolute_url())
    else:
        form = AccountForm(instance=account, user=request.user)
    return render(request, "manager/account_form.html", {"form": form, "title": "Edit Apple account"})


def account_delete(request, pk):
    account = _get_account(request, pk)
    if request.method == "POST":
        try:
            account.delete()
            messages.success(request, "Apple account deleted.")
        except ProtectedError:
            messages.error(request, "Account still has devices; delete them first.")
            return redirect(account.get_absolute_url())
        return redirect("manager:account_list")
    return render(request, "manager/confirm_delete.html", {"object": account})


def _enqueue_login(account):
    from django_q.tasks import async_task

    return async_task("manager.tasks.login_findmy", account.pk)


def account_findmy_login(request, pk):
    """Queue the same Apple login as ``login_findmy``, then finish 2FA if needed."""
    account = _get_account(request, pk)
    progress = findmy_auth.load_pending_meta(account)

    if not account.password_is_set:
        messages.error(request, "Store the Apple ID password first.")
        return redirect(account.get_absolute_url())

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "cancel":
            findmy_auth.clear_pending(account)
            messages.info(request, "Apple sign-in cancelled.")
            return redirect(account.get_absolute_url())

        if action == "start":
            account.last_fetch_status = "logging_in"
            account.last_fetch_message = "Apple sign-in queued in the background."
            account.save(update_fields=["last_fetch_status", "last_fetch_message"])
            task_id = _enqueue_login(account)
            messages.success(
                request,
                "Apple sign-in queued in the background (task %s). "
                "Refresh this page when it finishes; complete 2FA here if Apple asks."
                % task_id)
            return redirect(account.get_absolute_url())

        if action == "request":
            result = findmy_auth.request_2fa(account, request.POST.get("method"))
            if result["status"] == "code_sent":
                messages.info(request, "Enter the verification code from %s."
                              % result["method"]["label"])
            else:
                messages.error(request, result.get("message") or "Could not request a code.")
            return redirect("manager:account_findmy_login", account.pk)

        if action == "submit":
            requested = progress.get("requested") or {}
            method_index = request.POST.get("method", requested.get("index"))
            result = findmy_auth.submit_2fa(
                account, method_index, request.POST.get("code", ""))
            if result["status"] == "logged_in":
                account.last_fetch_status = "ok"
                account.last_fetch_message = "Apple session cached. Location fetches can reuse it."
                account.save(update_fields=["last_fetch_status", "last_fetch_message"])
                messages.success(
                    request, "Signed in to Apple. Background fetches can reuse this session.")
                return redirect(account.get_absolute_url())
            messages.error(request, result.get("message") or "Verification failed.")
            return redirect("manager:account_findmy_login", account.pk)

        return redirect("manager:account_findmy_login", account.pk)

    return render(request, "manager/account_findmy_login.html", {
        "account": account,
        "methods": progress.get("methods") or [],
        "requested": progress.get("requested"),
        "findmy_session_cached": findmy_auth.session_cached(account),
        "login_in_progress": findmy_auth.login_in_progress(account),
        "login_queued": account.last_fetch_status == "logging_in"
        and not findmy_auth.login_in_progress(account),
    })


# --------------------------------------------------------------------------
# Devices
# --------------------------------------------------------------------------

def device_list(request):
    account_id = request.GET.get("account")
    devices = _devices(request)
    selected_account = None
    if account_id:
        selected_account = _parse_uuid(account_id)
        if selected_account:
            devices = devices.filter(account_id=selected_account)
    return render(request, "manager/device_list.html", {
        "devices": devices,
        "accounts": _accounts(request),
        "selected_account": selected_account,
    })


def device_detail(request, pk):
    device = _get_device(request, pk)
    latest = device.locations.order_by("-timestamp").first()
    return render(request, "manager/device_detail.html", {
        "device": device, "latest": latest,
    })


LOCATIONS_PER_PAGE = 25


def device_history(request, pk):
    """Location history page; rows are loaded by DataTables via AJAX."""
    device = _get_device(request, pk)
    return render(request, "manager/device_history.html", {
        "device": device,
        "location_count": device.locations.count(),
        "locations_per_page": LOCATIONS_PER_PAGE,
    })


class DeviceHistoryDatatable(BaseDatatableView):
    """Server-side DataTables feed for one device's location reports."""

    columns = [
        "timestamp",
        "latitude",
        "longitude",
        "horizontal_accuracy",
        "battery_level",
    ]
    order_columns = [
        "timestamp",
        "latitude",
        "longitude",
        "horizontal_accuracy",
        "status",
    ]
    max_display_length = 100

    def dispatch(self, request, *args, **kwargs):
        self.device = _get_device(request, kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_initial_queryset(self):
        return self.device.locations.all()

    def filter_queryset(self, qs):
        search = (self.request.GET.get("search[value]") or "").strip()
        if not search:
            return qs
        return qs.filter(
            Q(latitude__icontains=search)
            | Q(longitude__icontains=search)
            | Q(horizontal_accuracy__icontains=search)
        )

    def render_column(self, row, column):
        if column == "timestamp":
            when = timezone.localtime(row.timestamp)
            return when.strftime("%Y-%m-%d %H:%M:%S")
        if column == "latitude":
            return "{:.6f}".format(row.latitude)
        if column == "longitude":
            return "{:.6f}".format(row.longitude)
        if column == "horizontal_accuracy":
            if row.horizontal_accuracy is None:
                return "—"
            return "{} m".format(row.horizontal_accuracy)
        if column == "battery_level":
            return row.battery_level
        return super().render_column(row, column)


def device_create(request):
    accounts = _accounts(request)
    if request.method == "POST":
        form = DeviceForm(request.POST, user=request.user)
        if form.is_valid():
            device = form.save()
            messages.success(request, "Device created with a fresh keypair."
                            if form.cleaned_data["key_source"] == "generate"
                            else "Device created.")
            return redirect(device.get_absolute_url())
    else:
        initial = {}
        if account_id := request.GET.get("account"):
            initial["account"] = account_id
        elif accounts.count() == 1:
            initial["account"] = accounts.values_list("pk", flat=True)[0]
        form = DeviceForm(initial=initial, user=request.user)
    return render(request, "manager/device_form.html", {"form": form, "title": "New device"})


def device_update(request, pk):
    device = _get_device(request, pk)
    if request.method == "POST":
        form = DeviceForm(request.POST, instance=device, user=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Device updated.")
            return redirect(device.get_absolute_url())
    else:
        form = DeviceForm(instance=device, user=request.user,
                          initial={"key_source": "import",
                                   "advertisement_key_hex": device.advertisement_key_hex,
                                   "private_key_hex": device.private_key_hex})
    return render(request, "manager/device_form.html", {"form": form, "title": "Edit device"})


def device_delete(request, pk):
    device = _get_device(request, pk)
    if request.method == "POST":
        device.delete()
        messages.success(request, "Device deleted.")
        return redirect("manager:device_list")
    return render(request, "manager/confirm_delete.html", {"object": device})


# --------------------------------------------------------------------------
# Exports
# --------------------------------------------------------------------------

def device_export_micropython(request, pk):
    """Export a single device as a downloadable Micropython ``main.py``."""
    device = _get_device(request, pk)
    if not device.advertisement_key_hex:
        messages.error(request, "This device has no advertisement key yet.")
        return redirect(device.get_absolute_url())

    form = MicropythonExportForm(initial={
        "broadcast_duration_sec": device.broadcast_duration_sec,
        "sleep_duration_min": device.sleep_duration_min,
    })
    if request.method == "POST":
        form = MicropythonExportForm(request.POST)
        if form.is_valid():
            source = micropython.generate_main_py(
                device,
                broadcast_duration_sec=form.cleaned_data["broadcast_duration_sec"],
                sleep_duration_min=form.cleaned_data["sleep_duration_min"],
            )
            return _attachment(source, "{}.py".format(safe_filename(device.name)),
                               content_type="text/x-python")
    return render(request, "manager/export_micropython.html", {
        "device": device,
        "form": form,
        "preview": micropython.generate_main_py(device),
    })


def device_export_firmware(request, pk):
    """Export a device as native ESP-IDF ``main.c`` firmware with the key baked in.

    Unlike the MicroPython export this firmware can set the BLE random static
    address that carries key[0:6], so the tag is Find-My matchable.
    """
    device = _get_device(request, pk)
    if not device.advertisement_key_hex:
        messages.error(request, "This device has no advertisement key yet.")
        return redirect(device.get_absolute_url())

    form = FirmwareExportForm(initial={
        "broadcast_duration_sec": device.broadcast_duration_sec,
        "sleep_duration_min": device.sleep_duration_min,
    })
    if request.method == "POST":
        form = FirmwareExportForm(request.POST)
        if form.is_valid():
            source = esp_idf.generate_firmware_c(
                device,
                broadcast_duration_sec=form.cleaned_data["broadcast_duration_sec"],
                sleep_duration_min=form.cleaned_data["sleep_duration_min"],
            )
            return _attachment(source, "{}.c".format(safe_filename(device.name)),
                               content_type="text/x-c")
    return render(request, "manager/export_firmware.html", {
        "device": device,
        "form": form,
        "preview": esp_idf.generate_firmware_c(device),
    })


def device_export_arduino(request, pk):
    """Export a device as an Arduino-IDE sketch (``tag.ino``) with the key baked in.

    Same OpenHaystack beacon as the ESP-IDF export, but shaped as an Arduino
    sketch for the ESP32 Arduino core (which can set the BLE random static
    address and is therefore Find-My matchable).
    """
    device = _get_device(request, pk)
    if not device.advertisement_key_hex:
        messages.error(request, "This device has no advertisement key yet.")
        return redirect(device.get_absolute_url())

    form = FirmwareExportForm(initial={
        "broadcast_duration_sec": device.broadcast_duration_sec,
        "sleep_duration_min": device.sleep_duration_min,
    })
    if request.method == "POST":
        form = FirmwareExportForm(request.POST)
        if form.is_valid():
            source = arduino.generate_sketch_ino(
                device,
                broadcast_duration_sec=form.cleaned_data["broadcast_duration_sec"],
                sleep_duration_min=form.cleaned_data["sleep_duration_min"],
            )
            return _attachment(source, "{}.ino".format(safe_filename(device.name)),
                               content_type="text/x-c")
    return render(request, "manager/export_arduino.html", {
        "device": device,
        "form": form,
        "preview": arduino.generate_sketch_ino(device),
    })


def macless_keyfile(request):
    """Download a macless-haystack ``*.keys`` file for the given batch of devices."""
    account_id = request.GET.get("account")
    devices = _devices(request).filter(active=True)
    if account_id:
        devices = devices.filter(account_id=account_id)
    if not devices:
        if account_id:
            messages.error(request, "No active devices for this account.")
            return redirect("manager:device_list")
        messages.error(request, "No active devices to export.")
        return redirect("manager:device_list")
    content = Device.keyfile(devices)
    return _attachment(content, "findmy.keys")


def account_config_ini(account):
    """Ready-to-use ``data/config.ini`` snippet for the macless-haystack container."""
    password = account.get_password()
    return (
        "[Settings]\n"
        "appleid = {email}\n"
        "appleid_pass = {password}\n"
        "# anisette_url = http://anisette:6969\n"
        "# port = 6176\n"
        "# binding_address = 0.0.0.0\n"
    ).format(email=account.email, password=password)


def config_ini_download(request, pk):
    account = _get_account(request, pk)
    return _attachment(account_config_ini(account), "config.ini")


def safe_filename(name):
    import re
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_")
    return cleaned or "device"


# --------------------------------------------------------------------------
# Find My locations (django-q2 background fetching)
# --------------------------------------------------------------------------

FETCH_DAYS = 7
FETCH_MIN_DAYS, FETCH_MAX_DAYS = 1, 365


def _enqueue_fetch(account):
    from django_q.tasks import async_task

    return async_task("manager.tasks.fetch_locations", account.pk, FETCH_DAYS)


def account_fetch_locations(request, pk):
    """Enqueue a background fetch of Apple's location history for one account."""
    account = _get_account(request, pk)
    if request.method != "POST":
        return redirect(account.get_absolute_url())
    if not account.password_is_set:
        messages.error(request, "Store the Apple ID password first.")
        return redirect(account.get_absolute_url())
    task_id = _enqueue_fetch(account)
    messages.success(request, "Location fetch queued in the background (task %s)." % task_id)
    return redirect(account.get_absolute_url())


def fetch_all_locations(request):
    """Enqueue a background fetch for every account that can be fetched."""
    if request.method != "POST":
        return redirect("manager:account_list")
    queued = 0
    for account in _accounts(request).filter(active=True):
        if not account.password_is_set:
            continue
        _enqueue_fetch(account)
        queued += 1
    if queued:
        messages.success(request, "Queued %d background location fetch(es)." % queued)
    else:
        messages.error(request, "No accounts with a stored Apple ID password.")
    return redirect("manager:account_list")


def map_view(request):
    """Show the latest decrypted location of every active device on a Leaflet map."""
    account_id = request.GET.get("account")

    latest = (DeviceLocation.objects.select_related("device__account")
              .for_user(request.user)
              .filter(device__active=True)
              .order_by("device_id", "-timestamp"))
    if account_id:
        latest = latest.filter(device__account_id=account_id)
    markers = {}
    for loc in latest:
        markers.setdefault(loc.device_id, loc)
    if not markers:
        messages.info(request, "No location data yet. Use 'Fetch now' to pull reports from Apple.")

    marker_data = [
        {
            "name": loc.device.name,
            "account": loc.device.account.name,
            "lat": loc.latitude,
            "lon": loc.longitude,
            "ts": loc.timestamp.isoformat(),
            "accuracy": loc.horizontal_accuracy,
            "battery": loc.battery_level,
            "url": loc.device.get_absolute_url(),
        }
        for loc in sorted(markers.values(), key=lambda l: (l.device.account.name, l.device.name))
    ]

    devices_no_data = _devices(request).filter(active=True, locations__isnull=True).count()
    return render(request, "manager/map.html", {
        "markers": marker_data,
        "accounts": _accounts(request).filter(devices__active=True).distinct(),
        "selected_account": account_id,
        "devices_with_data": len(markers),
        "devices_no_data": devices_no_data,
    })