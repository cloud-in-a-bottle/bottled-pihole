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


@pytest.fixture(scope="session")
def admin_session(stack: OpenhostStack) -> requests.Session:
    """Open the app as the owner like a browser; returns the session, holding the `sid` cookie the auth proxy minted.

    The proxy answers the owner's first navigation with a redirect that sets Pi-hole's `sid` cookie. That cookie is
    `Secure` (production is https), so over the harness's plain http requests would never send it back, and every
    redirect would mint another session until Pi-hole runs out of API seats. Browsers treat *.localhost as secure and
    do send it; to do the same, the redirect is followed by hand with the sid copied in as a plain cookie.
    """
    session = stack.owner_session
    html = {"Accept": "text/html"}
    deadline = time.monotonic() + 120
    while True:
        try:
            login = session.get(f"{stack.url}/", headers=html, allow_redirects=False, timeout=30)
            if login.status_code == 302 and "sid" in login.cookies:
                break
            last = f"{login.status_code} Location={login.headers.get('Location')!r}: {login.text[:300]}"
        except requests.ConnectionError as exc:
            last = str(exc)
        if time.monotonic() > deadline:
            raise AssertionError(
                f"owner GET / was not an auto-login redirect setting a sid cookie: {last}\n\n"
                f"app logs:\n{stack.app_logs()[-5000:]}"
            )
        time.sleep(3)

    browser = requests.Session()
    browser.headers.update(session.headers)
    for cookie in session.cookies:
        if cookie.name not in ("sid", "csrf"):  # the owner session just stored them too, as Secure cookies
            browser.cookies.set_cookie(cookie)
    host = urlparse(stack.url).hostname
    assert host is not None
    for name in ("sid", "csrf"):
        if name in login.cookies:
            browser.cookies.set(name, login.cookies[name], domain=host, path="/")
    dashboard = browser.get(f"{stack.url}{login.headers['Location']}", headers=html, timeout=30)
    path = urlparse(dashboard.url).path
    assert dashboard.status_code == 200 and path.startswith("/admin") and not path.startswith("/admin/login"), (
        f"after auto-login the owner ended at {path!r} (status {dashboard.status_code}), expected the dashboard, "
        f"not Pi-hole's login form /admin/login: {dashboard.text[:300]}\n\napp logs:\n{stack.app_logs()[-5000:]}"
    )
    return browser
