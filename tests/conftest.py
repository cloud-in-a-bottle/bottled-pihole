import http.cookiejar
import time
from collections.abc import Iterator
from urllib.parse import urlparse

import pytest
import requests
from openhost_test_harness import OpenhostStack


@pytest.fixture(scope="session")
def stack() -> Iterator[OpenhostStack]:
    """Builds the Dockerfile and deploys the app through the real router; returns once the app is running."""
    with OpenhostStack() as s:
        yield s


def _browser_session(stack: OpenhostStack) -> requests.Session:
    """A copy of the owner session that, like a browser on http://*.localhost, sends Secure cookies over http.

    The auth proxy sets Pi-hole's `sid` cookie with `Secure` (production is https); the harness serves the zone over
    http, where requests would otherwise drop it and the proxy would keep minting new sessions.
    """
    session = requests.Session()
    session.headers.update(stack.owner_session.headers)
    session.cookies = requests.cookies.RequestsCookieJar(
        policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "wss", "http"))
    )
    for cookie in stack.owner_session.cookies:
        session.cookies.set_cookie(cookie)
    return session


@pytest.fixture(scope="session")
def admin_session(stack: OpenhostStack) -> requests.Session:
    """Open the app as the owner like a browser; returns the session, holding the `sid` cookie the auth proxy minted."""
    session = _browser_session(stack)
    deadline = time.monotonic() + 120
    while True:
        try:
            response = session.get(f"{stack.url}/", headers={"Accept": "text/html"}, timeout=30)
            path = urlparse(response.url).path
            if response.status_code == 200 and path.startswith("/admin") and not path.startswith("/admin/login"):
                break
        except requests.ConnectionError as exc:
            response, path = None, f"connection error: {exc}"
        if time.monotonic() > deadline:
            status = response.status_code if response is not None else None
            body = response.text[:500] if response is not None else ""
            raise AssertionError(
                f"owner GET / ended at {path!r} (status {status}), expected the dashboard at /admin/ "
                f"(Pi-hole's login form is /admin/login): {body}\n\napp logs:\n{stack.app_logs()[-5000:]}"
            )
        time.sleep(3)

    assert session.cookies.get("sid"), f"no Pi-hole sid cookie after auto-login: {[c.name for c in session.cookies]}"
    return session
