import contextlib
import sqlite3
import time

from openhost_test_harness import OpenhostStack

DOMAIN = "ads.upstream-coverage.test"


def test_settings_are_stored_in_app_data(stack: OpenhostStack) -> None:
    """Pi-hole's config and gravity DB (/etc/pihole) live in the app data dir, so they survive redeploys and updates."""
    # Log in to Pi-hole's API directly with the bootstrap password, independent of the owner auto-login.
    password = (stack.data_dir / "webpassword.txt").read_text().strip()
    session = stack.owner_session
    auth = session.post(f"{stack.url}/api/auth", json={"password": password}, timeout=30)
    assert auth.status_code == 200, f"Pi-hole API login: {auth.status_code}: {auth.text[:300]}"
    api_headers = {"X-FTL-SID": auth.json()["session"]["sid"]}
    try:
        added = session.post(
            f"{stack.url}/api/domains/deny/exact",
            json={"domain": DOMAIN, "comment": "upstream-coverage test"},
            headers=api_headers,
            timeout=30,
        )
        assert added.status_code in (200, 201), f"adding a denied domain: {added.status_code}: {added.text[:500]}"
    finally:
        session.delete(f"{stack.url}/api/auth", headers=api_headers, timeout=30)

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
