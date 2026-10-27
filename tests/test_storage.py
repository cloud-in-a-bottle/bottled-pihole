import contextlib
import sqlite3
import time

import requests
from openhost_test_harness import OpenhostStack

DOMAIN = "ads.upstream-coverage.test"


def test_settings_are_stored_in_app_data(stack: OpenhostStack, admin_session: requests.Session) -> None:
    """Pi-hole's config and gravity DB (/etc/pihole) live in the app data dir, so they survive redeploys and updates."""
    session, sid = admin_session, admin_session.cookies["sid"]
    api_headers = {"X-FTL-SID": sid, "X-FTL-CSRF": session.cookies.get("csrf") or ""}
    response = session.post(
        f"{stack.url}/api/domains/deny/exact",
        json={"domain": DOMAIN, "comment": "upstream-coverage test"},
        headers=api_headers,
        timeout=30,
    )
    assert response.status_code in (200, 201), f"adding a denied domain: {response.status_code}: {response.text[:500]}"

    gravity_db = stack.data_dir / "pihole" / "gravity.db"
    deadline = time.monotonic() + 30
    domains: list[str] = []
    while time.monotonic() < deadline:
        if gravity_db.exists():
            with contextlib.closing(sqlite3.connect(f"file:{gravity_db}?mode=ro", uri=True)) as db:
                domains = [row[0] for row in db.execute("SELECT domain FROM domainlist")]
            if DOMAIN in domains:
                return
        time.sleep(2)
    contents = sorted(p.name for p in gravity_db.parent.iterdir()) if gravity_db.parent.exists() else None
    raise AssertionError(
        f"{DOMAIN} not in {gravity_db} (exists: {gravity_db.exists()}, domains: {domains}, dir: {contents})"
    )
