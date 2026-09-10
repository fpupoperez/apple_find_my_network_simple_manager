"""DRF views for the Find My manager API (v1).

Authentication is provided by django-allauth's headless app client
(see ``config.settings`` and ``api/auth.py``); these views only expose the
Find My resources.
"""

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from manager import arduino, esp_idf, micropython
from manager.views import _parse_uuid, account_config_ini, safe_filename
from manager.models import AppleAccount, Device, DeviceLocation
from api.serializers import (
    AccountSerializer,
    DeviceKeysSerializer,
    DeviceLocationSerializer,
    DeviceSerializer,
    ExportSerializer,
    KeyFileSerializer,
    MapMarkerSerializer,
)

FETCH_DAYS = 7


def _queue_fetch(account):
    from django_q.tasks import async_task
    return async_task("manager.tasks.fetch_locations", account.pk, FETCH_DAYS)


def _queue_fetch_all(user):
    queued = 0
    for account in AppleAccount.objects.for_user(user).filter(active=True):
        if account.password_is_set:
            _queue_fetch(account)
            queued += 1
    return queued


# --------------------------------------------------------------------------
# Apple accounts
# --------------------------------------------------------------------------

class AccountViewSet(viewsets.ModelViewSet):
    queryset = AppleAccount.objects.prefetch_related("devices").all()
    serializer_class = AccountSerializer
    filterset_fields = ["active"]
    search_fields = ["name", "email"]

    def get_queryset(self):
        return AppleAccount.objects.prefetch_related("devices").for_user(self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=["get"], url_path="config.ini")
    def config_ini(self, request, pk=None):
        account = self.get_object()
        if not account.password_is_set:
            return Response(
                {"detail": "No Apple ID password stored for this account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({
            "filename": "config.ini",
            "content_type": "text/plain",
            "content": account_config_ini(account),
        })

    @action(detail=True, methods=["post"])
    def fetch(self, request, pk=None):
        account = self.get_object()
        if not account.password_is_set:
            return Response(
                {"detail": "Store the Apple ID password before fetching locations."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        task_id = _queue_fetch(account)
        return Response(
            {"detail": "Location fetch queued in the background.", "task_id": str(task_id)},
            status=status.HTTP_202_ACCEPTED,
        )


# --------------------------------------------------------------------------
# Devices
# --------------------------------------------------------------------------

class DeviceViewSet(viewsets.ModelViewSet):
    queryset = Device.objects.select_related("account").all()
    serializer_class = DeviceSerializer
    filterset_fields = ["account", "active"]
    search_fields = ["name", "description", "account__name"]
    ordering_fields = ["name", "created_at", "updated_at"]

    def get_queryset(self):
        return Device.objects.select_related("account").for_user(self.request.user)

    @action(detail=True, methods=["get"])
    def keys(self, request, pk=None):
        return Response(DeviceKeysSerializer(self.get_object()).data)

    def _export(self, request, fmt, generator, suffix, content_type):
        device = self.get_object()
        if not device.advertisement_key_hex:
            return Response(
                {"detail": "This device has no advertisement key yet."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        params = request.query_params or {}
        try:
            broadcast = int(params["broadcast"]) if params.get("broadcast") else None
            sleep = int(params["sleep"]) if params.get("sleep") else None
        except ValueError:
            return Response(
                {"detail": "broadcast/sleep must be integers."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if broadcast is not None and not 1 <= broadcast <= 3600:
            return Response({"detail": "broadcast must be between 1 and 3600 seconds."},
                            status=status.HTTP_400_BAD_REQUEST)
        if sleep is not None and not 1 <= sleep <= 1440:
            return Response({"detail": "sleep must be between 1 and 1440 minutes."},
                            status=status.HTTP_400_BAD_REQUEST)

        source = generator(
            device,
            broadcast_duration_sec=broadcast,
            sleep_duration_min=sleep,
        )
        return Response(ExportSerializer({
            "device": device.pk,
            "fmt": fmt,
            "filename": "{}.{}".format(safe_filename(device.name), suffix),
            "content_type": content_type,
            "content": source,
        }).data)

    @action(detail=True, methods=["get", "post"], url_path="export/micropython")
    def export_micropython(self, request, pk=None):
        return self._export(
            request, "micropython", micropython.generate_main_py, "py", "text/x-python")

    @action(detail=True, methods=["get", "post"], url_path="export/firmware")
    def export_firmware(self, request, pk=None):
        return self._export(
            request, "firmware", esp_idf.generate_firmware_c, "c", "text/x-c")

    @action(detail=True, methods=["get", "post"], url_path="export/arduino")
    def export_arduino(self, request, pk=None):
        return self._export(
            request, "arduino", arduino.generate_sketch_ino, "ino", "text/x-c")


# --------------------------------------------------------------------------
# Device locations
# --------------------------------------------------------------------------

class DeviceLocationViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = (DeviceLocation.objects
                .select_related("device__account")
                .filter(device__active=True))
    serializer_class = DeviceLocationSerializer
    filterset_fields = ["device", "device__account", "status"]
    ordering_fields = ["timestamp", "created_at"]

    def get_queryset(self):
        return (DeviceLocation.objects
                .select_related("device__account")
                .for_user(self.request.user)
                .filter(device__active=True))


# --------------------------------------------------------------------------
# Map & batch exports (single-responsibility views)
# --------------------------------------------------------------------------

class MapView(APIView):
    """Latest decrypted location of every active device, like the web map."""

    def get(self, request):
        account_id = request.query_params.get("account")
        latest = (DeviceLocation.objects.select_related("device__account")
                  .for_user(request.user)
                  .filter(device__active=True)
                  .order_by("device_id", "-timestamp"))
        if account_id:
            account_uuid = _parse_uuid(account_id)
            if account_uuid is None:
                return Response({"detail": "account must be a UUID."},
                                status=status.HTTP_400_BAD_REQUEST)
            latest = latest.filter(device__account_id=account_uuid)
        markers = {}
        for loc in latest:
            markers.setdefault(loc.device_id, loc)
        ordered = sorted(markers.values(),
                         key=lambda l: (l.device.account.name, l.device.name))
        return Response(MapMarkerSerializer(ordered, many=True).data)


class MaclessKeyfileView(APIView):
    """Download a macless-haystack ``*.keys`` file for a batch of devices."""

    def get(self, request):
        devices = Device.objects.filter(active=True).select_related("account").for_user(request.user)
        account_id = request.query_params.get("account")
        if account_id:
            account_uuid = _parse_uuid(account_id)
            if account_uuid is None:
                return Response({"detail": "account must be a UUID."},
                                status=status.HTTP_400_BAD_REQUEST)
            devices = devices.filter(account_id=account_uuid)
        devices = list(devices)
        if not devices:
            return Response({"detail": "No active devices to export."},
                            status=status.HTTP_404_NOT_FOUND)
        return Response(KeyFileSerializer({
            "filename": "findmy.keys",
            "content_type": "text/plain",
            "content": Device.keyfile(devices),
        }).data)


class FetchAllLocationsView(APIView):
    """Queue a background location fetch for every eligible account (POST)."""

    def post(self, request):
        queued = _queue_fetch_all(request.user)
        if not queued:
            return Response(
                {"detail": "No accounts with a stored Apple ID password."},
                status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {"detail": "Queued {} background location fetch(es).".format(queued)},
            status=status.HTTP_202_ACCEPTED)