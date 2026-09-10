"""URL routing for the Find My manager API under /api/v1/.

Authentication lives under /api/app/v1/ (django-allauth headless app client).
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from api.views import (
    AccountViewSet,
    DeviceLocationViewSet,
    DeviceViewSet,
    FetchAllLocationsView,
    MaclessKeyfileView,
    MapView,
)

app_name = "api"

router = DefaultRouter()
router.register(r"accounts", AccountViewSet, basename="account")
router.register(r"devices", DeviceViewSet, basename="device")
router.register(r"locations", DeviceLocationViewSet, basename="location")

urlpatterns = [
    path("", include(router.urls)),
    path("map/", MapView.as_view(), name="map"),
    path("keys/", MaclessKeyfileView.as_view(), name="keyfile"),
    path("fetch/", FetchAllLocationsView.as_view(), name="fetch_all"),
]