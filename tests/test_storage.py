import time
from pathlib import Path

from openhost_test_harness import OpenhostStack

DOMAIN = "ads.upstream-coverage.test"


def _gravity_db_mtime(pihole_dir: Path) -> int:
    """Newest mtime of gravity.db and its journal files. The files belong to the container's pihole user, so the
    test can stat them but not read them."""
    return max((p.stat().st_mtime_ns for p in pihole_dir.glob("gravity.db*")), default=0)


def test_settings_are_stored_in_app_data(stack: OpenhostStack) -> None:
    """Pi-hole's config and gravity DB (/etc/pihole) live in the app data dir, so they survive redeploys and updates."""
    pihole_dir = stack.data_dir / "pihole"
    assert (pihole_dir / "pihole.toml").exists(), f"app data dir: {sorted(p.name for p in stack.data_dir.iterdir())}"
    before = _gravity_db_mtime(pihole_dir)
    time.sleep(1.1)  # so a write lands on a later mtime even on coarse-timestamp filesystems

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

    deadline = time.monotonic() + 30
    while _gravity_db_mtime(pihole_dir) <= before:
        assert time.monotonic() < deadline, (
            f"adding a domain did not write {pihole_dir}/gravity.db; dir: {sorted(p.name for p in pihole_dir.iterdir())}"
        )
        time.sleep(1)
