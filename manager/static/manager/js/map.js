(async function () {
  const accountSelect = document.getElementById("account");
  const deviceSelect = document.getElementById("device");

  function initDeviceSelect() {
    if (!deviceSelect || typeof TomSelect === "undefined") {
      return;
    }
    const allDevices = Array.from(deviceSelect.options).map(function (option) {
      return {
        value: option.value,
        text: option.textContent.trim(),
        account: option.dataset.account || "",
      };
    });
    const ts = new TomSelect(deviceSelect, {
      plugins: {
        remove_button: { title: "Remove" },
        clear_button: { title: "Clear selection" },
      },
      maxOptions: null,
      hideSelected: true,
      closeAfterSelect: false,
      placeholder: "All devices",
      hidePlaceholder: true,
      render: {
        no_results: function () {
          return '<div class="no-results">No matching devices</div>';
        },
      },
    });

    function applyAccountFilter() {
      const account = accountSelect ? accountSelect.value : "";
      const allowed = allDevices.filter(function (device) {
        return !account || device.account === account;
      });
      const allowedValues = new Set(allowed.map(function (device) {
        return device.value;
      }));
      const kept = ts.getValue().filter(function (value) {
        return allowedValues.has(value);
      });
      ts.clear(true);
      ts.clearOptions();
      ts.addOptions(allowed);
      kept.forEach(function (value) {
        ts.addItem(value, true);
      });
      ts.refreshOptions(false);
    }

    if (accountSelect) {
      accountSelect.addEventListener("change", applyAccountFilter);
    }
    applyAccountFilter();
  }

  initDeviceSelect();

  const payloadEl = document.getElementById("map-data");
  if (!payloadEl) {
    return;
  }
  const payload = JSON.parse(payloadEl.textContent);
  const markers = payload.markers || [];
  const routes = payload.routes || [];
  const focus = payload.focus || null;

  // OpenFreeMap's "dark" style references sprite images (e.g. the fill
  // pattern "wood-pattern") that are missing from its sprite. Synthesise
  // fallbacks before the map is built so handlers can stay synchronous.
  const fallbackImages = {};

  function makePatternCanvas() {
    const c = document.createElement("canvas");
    c.width = c.height = 64;
    const x = c.getContext("2d");
    x.fillStyle = "rgba(101, 105, 61, 0.28)";
    x.fillRect(0, 0, 64, 64);
    x.strokeStyle = "rgba(48, 42, 24, 0.5)";
    x.lineWidth = 1;
    for (let i = 0; i < 9; i++) {
      const y = (i % 3) * 22 + 11;
      x.beginPath();
      x.moveTo(0, y);
      x.bezierCurveTo(16, y - 4, 48, y + 4, 64, y - 2);
      x.stroke();
    }
    return c;
  }

  function makeGlyphCanvas() {
    const c = document.createElement("canvas");
    c.width = c.height = 16;
    const x = c.getContext("2d");
    x.fillStyle = "rgba(88, 166, 255, 0.85)";
    x.beginPath();
    x.arc(8, 8, 5, 0, Math.PI * 2);
    x.fill();
    return c;
  }

  // ImageBitmap is the proper source for WebGL texImage2D — avoids the
  // "Alpha-premult and y-flip are deprecated for non-DOM-Element uploads"
  // warning that ImageData triggers.
  [fallbackImages.pattern, fallbackImages.glyph] =
    await Promise.all([
      createImageBitmap(makePatternCanvas()),
      createImageBitmap(makeGlyphCanvas()),
    ]);

  const ROUTE_START_COLOR = "#3fb950";
  const ROUTE_END_COLOR = "#f85149";

  function popupHtml(marker) {
    return "<div class='fmp-popup' style='border-top-color:" + (marker.color || "#58a6ff") + "'>"
      + "<a class='fmp-popup-title' href='" + marker.url + "'>" + marker.name + "</a>"
      + (marker.role ? "<div class='fmp-popup-row'><i class='bi " + marker.roleIcon + "'></i><span>" + marker.role + "</span></div>" : "")
      + (marker.account ? "<div class='fmp-popup-row'><i class='bi bi-person'></i><span>" + marker.account + "</span></div>" : "")
      + "<div class='fmp-popup-row'><i class='bi bi-clock'></i><span>" + new Date(marker.ts).toLocaleString() + "</span></div>"
      + (marker.accuracy != null ? "<div class='fmp-popup-row'><i class='bi bi-crosshair'></i><span>" + marker.accuracy.toFixed(0) + " m</span></div>" : "")
      + (marker.battery ? "<div class='fmp-popup-row'><i class='bi bi-battery-charging'></i><span>" + marker.battery + "</span></div>" : "")
      + "</div>";
  }

  function collectBounds() {
    const bounds = new maplibregl.LngLatBounds();
    let hasPoint = false;
    for (const marker of markers) {
      bounds.extend([marker.lon, marker.lat]);
      hasPoint = true;
    }
    for (const route of routes) {
      for (const coord of route.coordinates || []) {
        bounds.extend(coord);
        hasPoint = true;
      }
    }
    return hasPoint ? bounds : null;
  }

  function addRoutes(map) {
    if (!routes.length || map.getSource("device-routes")) {
      return;
    }
    map.addSource("device-routes", {
      type: "geojson",
      data: {
        type: "FeatureCollection",
        features: routes.map(function (route) {
          return {
            type: "Feature",
            properties: { color: route.color, name: route.name },
            geometry: { type: "LineString", coordinates: route.coordinates },
          };
        }),
      },
    });
    map.addLayer({
      id: "device-routes-casing",
      type: "line",
      source: "device-routes",
      layout: { "line-join": "round", "line-cap": "round" },
      paint: { "line-color": "#0d1117", "line-width": 5, "line-opacity": 0.75 },
    });
    map.addLayer({
      id: "device-routes-line",
      type: "line",
      source: "device-routes",
      layout: { "line-join": "round", "line-cap": "round" },
      paint: {
        "line-color": ["get", "color"],
        "line-width": 3,
        "line-opacity": 0.9,
      },
    });
    addRouteMidpoints(map);
  }

  function routePointFeatures() {
    const features = [];
    for (const route of routes) {
      const points = route.points || [];
      if (points.length < 3) {
        continue;
      }
      const latest = markers.find(function (marker) {
        return marker.id === route.id;
      });
      for (let i = 1; i < points.length - 1; i++) {
        const point = points[i];
        features.push({
          type: "Feature",
          properties: {
            name: route.name,
            url: latest ? latest.url : "#",
            account: latest ? latest.account : "",
            ts: point.ts,
            accuracy: point.accuracy == null ? "" : point.accuracy,
            battery: point.battery || "",
            color: route.color,
          },
          geometry: { type: "Point", coordinates: [point.lon, point.lat] },
        });
      }
    }
    return features;
  }

  function addRouteMidpoints(map) {
    const features = routePointFeatures();
    if (!features.length || map.getSource("device-route-midpoints")) {
      return;
    }
    map.addSource("device-route-midpoints", {
      type: "geojson",
      data: { type: "FeatureCollection", features: features },
    });
    map.addLayer({
      id: "device-route-midpoints",
      type: "circle",
      source: "device-route-midpoints",
      paint: {
        "circle-radius": 6,
        "circle-color": "#e6edf3",
        "circle-stroke-width": 2,
        "circle-stroke-color": ["get", "color"],
        "circle-opacity": 0.95,
      },
    });
    map.addLayer({
      id: "device-route-midpoints-hit",
      type: "circle",
      source: "device-route-midpoints",
      paint: {
        "circle-radius": 14,
        "circle-color": "#ffffff",
        "circle-opacity": 0,
      },
    });
    const popup = new maplibregl.Popup({ offset: 12, closeButton: false });
    function openPointPopup(event) {
      const feature = event.features && event.features[0];
      if (!feature) {
        return;
      }
      const props = feature.properties || {};
      const accuracy = props.accuracy === "" || props.accuracy == null
        ? null
        : Number(props.accuracy);
      popup
        .setLngLat(feature.geometry.coordinates)
        .setHTML(popupHtml({
          name: props.name,
          url: props.url,
          account: props.account,
          ts: props.ts,
          accuracy: Number.isFinite(accuracy) ? accuracy : null,
          battery: props.battery,
          color: props.color,
          role: "Report",
          roleIcon: "bi-record-circle",
        }))
        .addTo(map);
    }
    map.on("click", "device-route-midpoints-hit", openPointPopup);
    map.on("mouseenter", "device-route-midpoints-hit", function () {
      map.getCanvas().style.cursor = "pointer";
    });
    map.on("mouseleave", "device-route-midpoints-hit", function () {
      map.getCanvas().style.cursor = "";
    });
  }

  function addMarker(map, lngLat, color, html, scale) {
    const marker = new maplibregl.Marker({ color: color, scale: scale || 1 })
      .setLngLat(lngLat)
      .setPopup(new maplibregl.Popup({ offset: scale && scale < 1 ? 20 : 28, closeButton: false }))
      .addTo(map);
    marker.getPopup().setHTML(html);
    return marker;
  }

  function addMarkers(map) {
    const byId = {};
    const routedIds = {};
    for (const route of routes) {
      if ((route.coordinates || []).length >= 2) {
        routedIds[route.id] = route;
      }
    }
    for (const marker of markers) {
      byId[marker.id] = marker;
      const isEnd = Boolean(routedIds[marker.id]);
      const color = isEnd ? ROUTE_END_COLOR : (marker.color || "#58a6ff");
      addMarker(map, [marker.lon, marker.lat], color, popupHtml(Object.assign({}, marker, {
        color: color,
        role: isEnd ? "End" : "",
        roleIcon: "bi-geo-alt-fill",
      })));
    }
    for (const route of routes) {
      const coords = route.coordinates || [];
      if (coords.length < 2) {
        continue;
      }
      const latest = byId[route.id];
      addMarker(map, coords[0], ROUTE_START_COLOR, popupHtml({
        name: route.name,
        url: latest ? latest.url : "#",
        account: latest ? latest.account : "",
        ts: route.start_ts,
        color: ROUTE_START_COLOR,
        role: "Start",
        roleIcon: "bi-flag-fill",
      }), 0.85);
    }
    if (focus) {
      addMarker(map, [focus.lon, focus.lat], focus.color || "#d29922", popupHtml({
        name: focus.name,
        url: focus.url,
        account: focus.account,
        ts: focus.ts,
        accuracy: focus.accuracy,
        battery: focus.battery,
        color: focus.color || "#d29922",
        role: focus.role || "Selected report",
        roleIcon: "bi-pin-map-fill",
      })).togglePopup();
    }
  }

  // Defer map construction until the page is fully loaded: MapLibre
  // measures its container synchronously, and doing that before load forces
  // a layout that Chrome warns about ("Layout was forced before the page
  // was fully loaded...") and can flash unstyled content.
  function initMap() {
    const map = new maplibregl.Map({
      container: "map",
      style: "https://tiles.openfreemap.org/styles/dark",
      center: [-3.0, 40.0],
      zoom: 4,
    });
    map.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
    if (["127.0.0.1", "localhost"].includes(window.location.hostname)) {
      window.__map = map;
    }

    map.on("load", () => {
      const style = map.getStyle();
      const pats = new Set();
      for (const l of style.layers) {
        const p = l.paint;
        if (p && p["fill-pattern"]) pats.add(p["fill-pattern"]);
      }
      for (const id of pats) {
        if (!map.hasImage(id)) map.addImage(id, fallbackImages.pattern);
      }
      addRoutes(map);
      if (focus) {
        map.flyTo({
          center: [focus.lon, focus.lat],
          zoom: 15,
          essential: true,
        });
      } else {
        const bounds = collectBounds();
        if (bounds) {
          map.fitBounds(bounds, { padding: 48, maxZoom: 16 });
        }
      }
    });

    map.on("styleimagemissing", (e) => {
      const id = e.id;
      if (map.hasImage(id)) return;
      map.addImage(id, id.endsWith("-pattern") ? fallbackImages.pattern : fallbackImages.glyph);
    });

    addMarkers(map);
  }

  if (document.readyState === "complete") {
    initMap();
  } else {
    window.addEventListener("load", initMap);
  }
})();
