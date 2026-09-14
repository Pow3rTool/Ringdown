"""Favicon assets are packaged, routed publicly, and linked from the WebUI."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ringdown.webui import _FAVICON_ASSETS, _FAVICON_DIR, _PAGE, _logitem, build_app


def test_favicon_bundle_is_complete_and_routed():
    route_paths = {route.path for route in build_app().routes}
    assert set(_FAVICON_ASSETS) <= route_paths
    for url, (filename, media_type) in _FAVICON_ASSETS.items():
        asset = _FAVICON_DIR / filename
        assert asset.is_file(), f"{url} is missing {asset}"
        assert asset.stat().st_size > 0
        assert media_type.startswith(("image/", "application/"))


def test_manifest_and_page_metadata_are_ringdown_specific():
    manifest = json.loads((_FAVICON_DIR / "site.webmanifest").read_text())
    assert manifest["name"] == "Ringdown"
    assert manifest["short_name"] == "Ringdown"
    assert manifest["theme_color"] == "#0b0e14"
    assert manifest["background_color"] == "#0b0e14"
    assert manifest["start_url"] == "/"
    for url in _FAVICON_ASSETS:
        if url != "/favicon.ico":
            assert url in _PAGE or url in {
                icon["src"] for icon in manifest["icons"]
            }


def test_log_item_exposes_only_allowlisted_operator_attributes():
    item = _logitem({
        "ts": datetime(2026, 9, 8, tzinfo=timezone.utc),
        "source": "example-app",
        "severity": 13,
        "severity_text": "WARN",
        "program": "example-app",
        "body": "request failed",
        "attributes": {
            "event": "example.request.failed", "requestId": 123, "provider": "example-provider",
            "err": {"stack": "too much detail for the live feed"},
            "resource": {"service.name": "example-app"},
        },
    })
    assert item["attrs"] == {
        "event": "example.request.failed", "requestId": 123, "provider": "example-provider",
    }
